# HTTP Journey Load Tests

External black-box load tests for the ApexMail API server, implemented as **k6 scripts**.

These tests exercise the API server end-to-end through its public HTTP interface, covering
middleware, authentication, request routing, serialization, business logic, and database I/O —
the full request path that in-process Rust unit tests cannot measure.

## Coverage

| Script | Endpoint | Type |
|--------|----------|------|
| [`auth-load-test.js`](auth-load-test.js) | `POST /v1/auth/login` | Authentication |
| [`email-send-load-test.js`](email-send-load-test.js) | `POST /v1/messages` | Email sending |
| [`health-load-test.js`](health-load-test.js) | `GET /health/live`, `GET /health/ready` | Health checks |
| [`tracking-pixel-test.js`](tracking-pixel-test.js) | `GET /v1/tracking/pixel.gif`, `GET /v1/tracking/click.gif` | Tracking pixel throughput |
| [`combined-journey-test.js`](combined-journey-test.js) | All of the above (weighted distribution) | Full journey |

## Pre-requisites

1. **k6 installed** — [Installation guide](https://k6.io/docs/get-started/installation/)
   ```sh
   # macOS (Homebrew)
   brew install k6

   # Linux (Debian/Ubuntu)
   sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
   echo "deb https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
   sudo apt-get update && sudo apt-get install k6
   ```

2. **ApexMail API server running** — The API server must be reachable at the target base URL.
   - Local development: default `http://localhost:3000`
   - Staging: set `K6_API_BASE` environment variable (see below)

3. **Database and dependencies** — The API server must have its backing services
   (PostgreSQL, Redis, etc.) running and healthy.

## Running Individual Scripts

Each script can be run independently with the `k6 run` command.

### Auth Load Test

```sh
# Default (localhost)
k6 run auth-load-test.js

# Custom base URL
K6_API_BASE=http://staging.apexmail.ee k6 run auth-load-test.js
```

Tests `POST /v1/auth/login` with simulated user credentials.  
Concurrency levels: 10 → 50 → 100 concurrent users (ramp-up over 8 minutes, sustain 5 minutes).

### Email Send Load Test

```sh
# Default (localhost)
K6_API_KEY=your-api-key k6 run email-send-load-test.js

# Custom base URL + API key
K6_API_BASE=http://staging.apexmail.ee K6_API_KEY=xxx k6 run email-send-load-test.js
```

Tests `POST /v1/messages` with dynamically generated email payloads.  
Requires an API key (`K6_API_KEY`) for the `Authorization: Bearer` header.  
Concurrency levels: 10 → 50 → 100 concurrent users.

### Health Load Test

```sh
k6 run health-load-test.js
```

Tests `GET /health/live` and `GET /health/ready`.  
No authentication required — health endpoints are meant for unauthenticated
orchestrator probes.  
Concurrency levels: 10 → 50 → 100 concurrent users (shorter duration — health
checks are lightweight).

### Combined Journey Test

```sh
K6_API_KEY=your-api-key k6 run combined-journey-test.js
```

Runs all four API paths with a realistic traffic mix:
| Endpoint | Weight | Rationale |
|----------|--------|-----------|
| `GET /health/live` | 10% | Orchestrator polling frequency |
| `GET /health/ready` | 10% | Orchestrator polling frequency |
| `POST /v1/auth/login` | 30% | Session initiation |
| `POST /v1/messages` | 50% | Primary business operation |

Concurrency levels: 10 → 50 → 100 concurrent users.

## Output and Results

Each script outputs real-time metrics to stdout as VUs progress through stages:

```
     /\      |‾‾| /‾‾/   /‾‾/
    /  \     |  |/  /   /  /
   /    \    |     (   /   ‾‾\
  /      \   |  |\  \ |  (‾)  |
 / ________  |__| \__\ \_____/ .io

     execution: local
        script: combined-journey-test.js
        output: -

     scenarios: (100.00%) 1 scenario, 100 max VUs, 20m30s max duration (incl. graceful stop):
              * default: Up to 100 looping VUs for 15m0s over 5 stages (gracefulRampDown: 30s, startTime: 0s)


     ✓ auth login status is 200
     ✓ auth login has token
     ✓ email send status is 202
     ✓ email send has message_id
     ✓ liveness status is 200
     ✓ readiness status is 200

     █ Total
     checks.........................: 100.00% ✓ 15000   ✗ 0
     data_received..................: 15 MB  1.7 MB/s
     data_sent......................: 5.0 MB 556 kB/s
     http_req_blocked...............: avg=1.2ms   p(95)=4.5ms
     http_req_connecting............: avg=0.8ms   p(95)=3.2ms
     http_req_duration..............: avg=120ms   p(95)=340ms  p(99)=780ms
     http_req_failed................: 0.00%  ✓ 0       ✗ 15000
     auth_login_duration............: avg=145ms   p(95)=380ms
     email_send_duration............: avg=135ms   p(95)=410ms
     liveness_duration..............: avg=12ms    p(95)=25ms
     readiness_duration.............: avg=15ms    p(95)=30ms
     error_rate.....................: 0.00%  ✓ 0       ✗ 15000
     total_requests.................: 15000  1666/s
```

Key metrics to watch:
- **`http_req_duration`** — Overall request latency (p95, p99)
- **`http_req_failed`** — Overall error rate
- **`{endpoint}_duration`** — Per-endpoint latency trend
- **`error_rate`** — Per-endpoint error rate
- **`total_requests`** — Request throughput

## Target Thresholds

| Metric | Threshold | Severity |
|--------|-----------|----------|
| `http_req_duration` p(95) | < 500 ms | 🔴 hard fail |
| `http_req_duration` p(99) | < 1000 ms | 🟡 warn |
| `http_req_failed` | < 1% | 🔴 hard fail |
| `error_rate` | < 1% | 🔴 hard fail |
| `auth_login_duration` p(95) | < 500 ms | 🔴 hard fail |
| `email_send_duration` p(95) | < 500 ms | 🔴 hard fail |
| `liveness_duration` p(95) | < 200 ms | 🔴 hard fail |
| `readiness_duration` p(95) | < 200 ms | 🔴 hard fail |

> **Note**: Health endpoint thresholds are stricter (p95 < 200 ms) because health checks
> are called by orchestrators (k8s, load balancers) at high frequency and must be cheap.

## CI Integration Notes

> ⚠️ **This section documents how these scripts SHOULD be integrated into CI.**
> Actual CI workflow modifications are tracked as **D-03** (separate item).

### Integration Points

These scripts are designed to run in the existing [`load-gate.yml`](../../.github/workflows/load-gate.yml)
workflow alongside the Rust load tests. The recommended integration:

1. **Add a CI job step** after the existing k6 API tests that runs each script individually
   and/or the combined journey test:

   ```yaml
   - name: Run HTTP journey load tests
     working-directory: load-tests/http-journey
     run: |
       for script in auth-load-test.js email-send-load-test.js health-load-test.js combined-journey-test.js; do
         echo "=== Running $script ==="
         K6_API_BASE=http://localhost:3000 K6_API_KEY=${{ secrets.LOAD_TEST_API_KEY }} \
           k6 run "$script" \
           --out json=/tmp/http-journey-${script%.js}.json \
           2>&1 | tee -a http-journey-output.log
       done
   ```

2. **Threshold checking** — k6 exits with non-zero if thresholds are exceeded.
   The CI step will automatically fail, but explicit logging is recommended:

   ```yaml
   - name: Check HTTP journey thresholds
     run: |
       if grep -q "thresholds on metrics 'http_req_duration'" http-journey-output.log; then
         echo "❌ HTTP journey test thresholds exceeded!"
         exit 1
       fi
       echo "✅ All HTTP journey tests passed!"
   ```

### Expected Baseline Values

On a standard GitHub Actions runner (2 vCPU, 7 GB RAM) with local services:

| Script | Expected throughput | Expected p95 |
|--------|-------------------|--------------|
| `auth-load-test.js` | ~500 req/s | < 300 ms |
| `email-send-load-test.js` | ~200 req/s | < 400 ms |
| `health-load-test.js` | ~2000 req/s | < 50 ms |
| `combined-journey-test.js` | ~300 req/s | < 400 ms |

On dedicated production-scale hardware (4 vCPU, 16 GB RAM), expect 3-5× improvement.

### Graceful Failure

Scripts are designed to fail gracefully:
- **Timeout**: Each script has a 20m30s max duration — CI jobs should set `timeout-minutes: 25`
- **No API server**: If the server is unreachable, k6 reports 100% error rate and thresholds fail
- **Partial results**: The combined journey test continues running even if one endpoint fails

## Concurrency Model

All scripts use k6 **staged ramp-up** to simulate realistic load patterns:

```
VUs
 100 ┤                                 ╱╲
  50 ┤                            ╱╲  ╱  ╲
  10 ┤                       ╱╲  ╱  ╲╱    ╲
   0 ┼───┬───┬───┬───┬───┬───┬───┬───────┬───▶ time
      2m  5m  8m 10m 12m 14m  15m  17m   19m
```

This avoids cold-start thundering herd problems and gives the API server time to
warm up caches, connection pools, and JIT compilation.

## Test Data Isolation

- Each VU generates unique test data using `__VU` (Virtual User ID) and `Date.now()`
- Email send payloads include unique sender addresses per VU
- Auth login uses deterministic credentials per VU (`user-{VU}@apexmail.ee`)
- No cross-VU state sharing — tests are idempotent at the VU level

## Production-Scale Testing

> ⚠️ **Production-scale tests generate significant load.** Run these only against
> dedicated staging or production-like environments. Do **not** run against shared
> development databases or under-powered CI runners.

### Infrastructure Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| k6 worker (where k6 runs) | 2 vCPU, 4 GB RAM | 4 vCPU, 8 GB RAM |
| API server nodes | 2 × 4 vCPU, 8 GB RAM | 4 × 8 vCPU, 16 GB RAM |
| PostgreSQL | 4 vCPU, 16 GB RAM, SSD | 8 vCPU, 32 GB RAM, NVMe SSD |
| Redis | 2 vCPU, 4 GB RAM | 4 vCPU, 8 GB RAM |
| Network bandwidth | 1 Gbps | 10 Gbps |
| Load balancer connection pool | 5000 concurrent | 10000 concurrent |

### Running Production-Scale Tests

#### 1. Distributed k6 (high throughput)

For throughput exceeding 10,000 req/s, use k6 in distributed mode:

```sh
# Start k6 operator (requires k6-operator on Kubernetes)
kubectl apply -f deploy/load-test-infra/k6-crd.yaml

# Deploy distributed test run
k6-operator run --name tracking-pixel-test \
  --parallelism 4 \
  --separate \
  load-tests/http-journey/tracking-pixel-test.js
```

#### 2. Single-node with high concurrency

```sh
# Override concurrency settings for production-scale
K6_API_BASE=http://staging.apexmail.ee \
  K6_API_KEY=your-api-key \
  k6 run tracking-pixel-test.js \
  --vus 5000 \
  --duration 10m \
  --out json=results/tracking-pixel-production.json \
  --out csv=results/tracking-pixel-production.csv
```

#### 3. Combined journey at scale

```sh
K6_API_BASE=http://staging.apexmail.ee \
  K6_API_KEY=your-api-key \
  k6 run combined-journey-test.js \
  --vus 3000 \
  --duration 15m \
  --out json=results/combined-production.json
```

### Production-Scale Test Plans

| Plan | Script | VUs | Duration | Expected Throughput | Test Cadence |
|------|--------|-----|----------|---------------------|-------------|
| Smoke test | `health-load-test.js` | 100 | 2m | ~2000 req/s | Per deployment |
| Baseline | `combined-journey-test.js` | 1000 | 10m | ~1000 req/s | Weekly |
| Peak simulation | `combined-journey-test.js` | 3000 | 15m | ~3000 req/s | Pre-release |
| Burst | `tracking-pixel-test.js` | 5000 | 10m | ~10000 req/s | Pre-release |
| Stress test | `combined-journey-test.js` | 5000 | 20m | ~5000 req/s | Monthly |
| Soak test | `combined-journey-test.js` | 2000 | 60m | ~2000 req/s | Monthly |

### Collecting Production-Scale Results

1. **k6 JSON output** — Enables detailed post-processing:
   ```sh
   k6 run ... --out json=results/test-$(date +%Y%m%d-%H%M%S).json
   ```

2. **Prometheus remote write** — Stream metrics in real-time:
   ```sh
   K6_PROMETHEUS_REMOTE_URL=http://prometheus.apexmail.ee:9090/api/v1/write \
   k6 run ... --out output-prometheus-remote
   ```

3. **Grafana dashboard** — Visualise live results using the
   [`load-testing-overview.json`](../../deploy/grafana/dashboards/load-testing-overview.json)
   dashboard in the `deploy/grafana/dashboards/` directory.

4. **Baseline comparison** — Compare against stored baselines:
   ```sh
   # After test completes, compare results
   k6 run ... --summary-export=results/current-summary.json
   # Compare against baseline
   ./scripts/compare-baseline.sh results/current-summary.json \
     --baseline load-tests/baselines/v1.0.json
   ```

### Expected Throughput Baselines

On the recommended production infrastructure (4 × 8 vCPU API servers, 8 vCPU PostgreSQL):

| Script | Expected Throughput | Expected p95 | Expected p99 |
|--------|-------------------|--------------|--------------|
| `auth-load-test.js` | ~2500 req/s | < 200 ms | < 400 ms |
| `email-send-load-test.js` | ~1000 req/s | < 300 ms | < 600 ms |
| `health-load-test.js` | ~10000 req/s | < 30 ms | < 50 ms |
| `combined-journey-test.js` | ~3000 req/s | < 250 ms | < 500 ms |
| `tracking-pixel-test.js` | ~10000 req/s | < 50 ms | < 100 ms |

### Graceful Degradation Under Load

These tests verify ApexMail's graceful degradation behaviour:

1. **Rate limiting** — At ~2× expected peak throughput, the API should return
   HTTP 429 with `Retry-After` headers rather than 5xx errors.
2. **Connection pooling** — At high concurrency (> 2000 VUs), PgBouncer or
   application-level connection pooling should prevent PostgreSQL connection
   exhaustion.
3. **Backpressure** — When the message queue backs up, the API should continue
   accepting requests but throttle email submission via queue-depth awareness.
4. **Circuit breakers** — If a downstream dependency (e.g., spam filter) degrades,
   the circuit breaker should open and serve degraded responses instead of
   cascading failures.

### Post-Test Analysis

After each production-scale test run:

1. Check all SLO compliance metrics in the
   [`slo-compliance.json`](../../deploy/monitoring/dashboards/slo-compliance.json) dashboard.
2. Review PostgreSQL `pg_stat_statements` for regressed query plans.
3. Compare latency histograms against the previous baseline.
4. Verify no connection leaks (PgBouncer `clients_waiting` should return to 0).
5. Check Redis memory usage and eviction rates.
6. Document findings in the test run report and update baselines.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| All requests fail with connection refused | API server not running | Start the API server: `cargo run -p api-server` |
| Auth tests fail with 401 | Wrong API key | Set `K6_API_KEY` env var |
| High latency (> 1s p95) | Resource contention or missing indexes | Check database CPU/memory, review slow query log |
| Health tests fail | Server not fully initialized | Wait for readiness probe to pass |
