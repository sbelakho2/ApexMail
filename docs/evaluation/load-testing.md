# Load Testing Strategy

> Internal document — Bel Consulting OÜ
>
> **Last updated:** 2026-05-12
> **Owner:** Platform Engineering

## Overview

This document defines the load-testing strategy for ApexMail. Every release that touches the tracking service hot-paths **must** pass the gate tests described here before promotion to production.

---

## Tooling

| Tool | Purpose |
|------|---------|
| **Rust load-tests crate** | Primary load generator — native Rust with async/await (in-process throughput) |
| **k6** | HTTP-level and browser-level load tests for API journey coverage |
| **Criterion** | Microbenchmarks for hot paths |
| **Prometheus + Grafana** | Real-time observation during test runs (dedicated `load-testing-overview` dashboard) |
| **Mailpit** | Mock SMTP server for capturing emails during load tests |

### Test Script Locations

| Type | Location |
|------|----------|
| Rust unit-level throughput tests | [`services/mail-server/crates/load-tests/tests/`](../../services/mail-server/crates/load-tests/tests) |
| Rust performance benchmarks | [`services/mail-server/crates/perf-tests/`](../../services/mail-server/crates/perf-tests) |
| k6 API journey tests | [`services/mail-server/crates/load-tests/tests/k6/`](../../services/mail-server/crates/load-tests/tests/k6) |
| k6 browser-level SSR tests | [`services/mail-server/crates/load-tests/tests/k6/browser-ssr-test.js`](../../services/mail-server/crates/load-tests/tests/k6/browser-ssr-test.js) |
| k6 tracking pixel tests | [`services/mail-server/crates/load-tests/tests/k6/tracking-pixel-test.js`](../../services/mail-server/crates/load-tests/tests/k6/tracking-pixel-test.js) |
| k6 billing tests | [`services/mail-server/crates/load-tests/tests/k6/billing-load-test.js`](../../services/mail-server/crates/load-tests/tests/k6/billing-load-test.js) |
| Baseline files | [`docs/evaluation/baselines/`](baselines) |
| Grafana dashboard | [`deploy/grafana/dashboards/load-testing-overview.json`](../../deploy/grafana/dashboards/load-testing-overview.json) |
| CI integration | manual/periodic (archived with the GitHub workflows — see `.github/workflows-archive/` and `ci/README.md` §2) |
| Docker Compose environment | [`deploy/load-test-infra/docker-compose.yml`](../../deploy/load-test-infra/docker-compose.yml) |

### Running Load Tests

```bash
# Rust unit-level load tests (release mode for realistic performance)
cd services/mail-server
cargo test -p load-tests --release -- --nocapture

# Rust performance benchmarks
cargo test -p perf-tests --release -- --nocapture

# k6 API journey tests
cd services/mail-server/crates/load-tests/tests/k6
k6 run api-load-test.js
k6 run full-journey-test.js
k6 run tracking-pixel-test.js

# k6 browser-level SSR tests (requires k6 browser module)
k6 run browser-ssr-test.js

# k6 billing tests
k6 run billing-load-test.js

# Full environment setup
./deploy/load-test-infra/setup.sh
```

---

## Test Scenarios

### 1. API Throughput — Rust Unit-Level

Exercises in-process throughput for core library operations (ID generation, email validation, prediction scoring, pattern matching, billing calculations, trust scoring). These are the **CI gate** tests that run on every push.

| Scenario | Minimum Throughput | Location |
|----------|-------------------|----------|
| ID generation | 10,000 ops/sec | [`load_throughput.rs`](../../services/mail-server/crates/load-tests/tests/load_throughput.rs) |
| Email validation | 50,000 ops/sec | [`load_throughput.rs`](../../services/mail-server/crates/load-tests/tests/load_throughput.rs) |
| Prediction scoring | 5,000 ops/sec | [`load_throughput.rs`](../../services/mail-server/crates/load-tests/tests/load_throughput.rs) |
| Pattern matching | 10,000 ops/sec | [`load_throughput.rs`](../../services/mail-server/crates/load-tests/tests/load_throughput.rs) |
| Billing calculations | 50,000 ops/sec | [`load_throughput.rs`](../../services/mail-server/crates/load-tests/tests/load_throughput.rs) |
| Trust scoring | 50,000 ops/sec | [`load_throughput.rs`](../../services/mail-server/crates/load-tests/tests/load_throughput.rs) |

### 2. API Journey Coverage — k6 HTTP Tests

End-to-end HTTP journey tests exercising all major API endpoints via external black-box testing. These run against a deployed staging environment.

| Flow | Endpoints | Weight | k6 Script |
|------|-----------|--------|-----------|
| 1. Auth | `POST /v1/auth/login`, `POST /v1/auth/refresh` | 5% | [`full-journey-test.js`](../../services/mail-server/crates/load-tests/tests/k6/full-journey-test.js) |
| 2. Email Send | `POST /v1/email/send` | 25% | [`full-journey-test.js`](../../services/mail-server/crates/load-tests/tests/k6/full-journey-test.js), [`api-load-test.js`](../../services/mail-server/crates/load-tests/tests/k6/api-load-test.js) |
| 3. Email List + Analytics | `GET /v1/email`, `GET /v1/analytics/summary` | 20% | [`full-journey-test.js`](../../services/mail-server/crates/load-tests/tests/k6/full-journey-test.js), [`api-load-test.js`](../../services/mail-server/crates/load-tests/tests/k6/api-load-test.js) |
| 4. Template CRUD | `POST/GET/PUT/DELETE /v1/templates` | 20% | [`full-journey-test.js`](../../services/mail-server/crates/load-tests/tests/k6/full-journey-test.js), [`api-load-test.js`](../../services/mail-server/crates/load-tests/tests/k6/api-load-test.js) |
| 5. Suppression Management | `POST/GET/DELETE /v1/suppressions` | 15% | [`full-journey-test.js`](../../services/mail-server/crates/load-tests/tests/k6/full-journey-test.js) |
| 6. Domain Management | `GET/POST /v1/domains` | 15% | [`full-journey-test.js`](../../services/mail-server/crates/load-tests/tests/k6/full-journey-test.js), [`api-load-test.js`](../../services/mail-server/crates/load-tests/tests/k6/api-load-test.js) |
| SMTP Submission | `POST /v1/email/send` (SMTP proxy) | — | [`smtp-load-test.js`](../../services/mail-server/crates/load-tests/tests/k6/smtp-load-test.js) |

**Targets:**

| Parameter | Target |
|-----------|--------|
| Virtual users | Ramp 0 → 50 → 100 → 200 over 10 min, hold 5 min |
| Request rate | 1,000 rps sustained |
| p95 latency | < 200 ms |
| p99 latency | < 500 ms |
| Error rate | < 0.1% |

### 3. Tracking Pixel & Click Tracking

High-volume GET requests through the tracking service. Validates throughput, latency, and data integrity at scale.

| Parameter | Target |
|-----------|--------|
| Request rate | 10,000 rps |
| p95 latency | < 50 ms |
| p99 latency | < 100 ms |
| Data loss | 0 — every event must reach the database |
| Error rate | < 0.1% |

**Endpoints under test:** [`tracking-pixel-test.js`](../../services/mail-server/crates/load-tests/tests/k6/tracking-pixel-test.js)

- `GET /t/{tracking_id}` — open pixel (70% weight)
- `GET /c/{tracking_id}` — click redirect (25% weight)
- `POST /u/{token}` — unsubscribe (5% weight)

**Data integrity validation:** The k6 script validates GIF89a headers for pixel responses and Location headers for click redirects.

### 4. Concurrent Users — SSR Browser Surfaces

Browser-level load for the Rust-served `control-plane` and `web` surfaces behind nginx. Uses k6's browser module for realistic page load measurements.

| Parameter | Target |
|-----------|--------|
| Concurrent sessions | 500 |
| Page load p95 | < 1.5 s (nginx cache warm) |
| Page load p99 | < 3.0 s |
| SSR render p95 | < 400 ms |
| SSR render p99 | < 1,000 ms |
| Error rate | < 2% |

**Pages under test:** [`browser-ssr-test.js`](../../services/mail-server/crates/load-tests/tests/k6/browser-ssr-test.js)

Control Plane: Dashboard, Analytics, Domains, Templates, Suppressions, Billing, Settings
Web: Email List, Compose, Analytics, Templates, Settings

### 5. Billing Calculations — Multi-Tenant Load

Tests billing calculations under concurrent tenant load. Exercises multi-tenant billing scenarios including plan calculations, overage costs, VAT, and invoice generation.

| Parameter | Target |
|-----------|--------|
| Concurrent tenants | 200 |
| Billing calc p95 | < 250 ms |
| Billing calc p99 | < 500 ms |
| Error rate | < 1% |

**Script:** [`billing-load-test.js`](../../services/mail-server/crates/load-tests/tests/k6/billing-load-test.js)

---

## Environment Setup

### Quick Start (Local/Docker)

```bash
# One-command provisioning
./deploy/load-test-infra/setup.sh

# Check status
./deploy/load-test-infra/setup.sh --status

# Tear down
./deploy/load-test-infra/setup.sh down
```

This provisions:

1. **PostgreSQL 16** — Isolated database (`apexmail_loadtest`) with schema initialized
2. **Redis 7** — Dedicated instance (maxmemory 512 MB, allkeys-lru eviction)
3. **Mailpit** — Mock SMTP server for capturing emails without real delivery
   - SMTP: `localhost:1025`
   - Web UI: `http://localhost:8025`
4. **init-db.sql** — Creates minimal schema (tenants, email_queue) and seeds test data

### Production-Scale (Hetzner Cloud)

For production-scale load testing, provision dedicated Hetzner Cloud ARM servers:

```bash
# Server specifications
# - API + SSR: CX42 (4 vCPU, 16 GB RAM)
# - Worker: CX32 (2 vCPU, 8 GB RAM)
# - Database: CX42 (4 vCPU, 16 GB RAM, 80 GB volume)

# See the Hetzner Simulation Checklist for full provisioning details:
# docs/deployment/HETZNER_SIMULATION_CHECKLIST.md
```

---

## Baselines

### Baseline Files

Performance baselines are stored at [`docs/evaluation/baselines/`](baselines).

| File | Type | Description |
|------|------|-------------|
| [`v0.1.json`](baselines/v0.1.json) | Full baseline | Initial baseline for all load and performance test scenarios |
| [`criterion-baseline.json`](baselines/criterion-baseline.json) | Microbenchmarks | Criterion benchmark baselines for hot-path operations |
| [`README.md`](baselines/README.md) | Specification | Baseline format specification and schema reference |

### Baseline Format

Baseline files follow a strict JSON schema. See [`docs/evaluation/baselines/README.md`](baselines/README.md) for the full specification.

Key sections:
- `meta` — Version, timestamp, environment metadata
- `api_throughput` — API request rate and latency targets
- `tracking_pixel` — Tracking pixel throughput and latency
- `ssr_browsers` — Browser-level rendering targets
- Component throughput sections (id_generation, email_validation, etc.)

### When to Update Baselines

| Trigger | Action |
|---------|--------|
| Major version bump (vX.0) | Full suite → new baseline |
| Minor version bump (v0.Y) | Full suite → new baseline |
| Quarterly (minimum) | Full suite → new baseline |
| Infrastructure change (Hetzner resize, PG upgrade) | Full suite → new baseline |
| Performance improvement merged | Verify improvement, update baseline |

---

## Regression Detection

### CI Workflow

Load-gate invocation (manual; deliberately outside the deploy gate — see `ci/README.md` §2):

```yaml
# Triggers:
#   - Push to main (reduced: 2 min hold)
#   - Pull request to main
#   - Release tag (full suite)
#   - Nightly schedule (full suite + baseline comparison)
#   - Weekly schedule (full suite + new baseline candidate)
#   - Manual workflow_dispatch
```

### When to Run

| Trigger | Scenarios |
|---------|-----------|
| PR merge to `main` | Rust load tests, k6 API tests |
| Pull request to `main` | Rust load tests, k6 API tests |
| Release candidate tag | Full suite (all k6 + Rust + browser) |
| Infrastructure change (Hetzner resize, PG upgrade) | Full suite |
| Nightly (02:00 UTC) | Full suite + baseline comparison |
| Weekly (Sunday 04:00 UTC) | Full suite + new baseline candidate |

### Threshold Validation

Any metric that degrades by more than **10%** compared to the active baseline triggers:

1. **CI gate failure** — the workflow exits with a non-zero code
2. **Slack notification** — posted to `#ops-load-testing` (via Slack webhook)
3. **Baseline exception** — requires engineering lead sign-off to override

### Comparison Tool

```bash
# Compare results against the latest baseline
./scripts/compare-baseline.sh results.json

# Compare against a specific baseline
./scripts/compare-baseline.sh results.json --baseline docs/evaluation/baselines/v0.1.json

# Verbose output
./scripts/compare-baseline.sh results.json --verbose
```

---

## Grafana Dashboard

Dashboard UID: `load-testing-overview`

Dashboard definition: [`deploy/grafana/dashboards/load-testing-overview.json`](../../deploy/grafana/dashboards/load-testing-overview.json)

### Panels

| Panel | Description |
|-------|-------------|
| Request Rate | Total, email send, tracking pixel, tracking click rates |
| Error Rate | 5xx and 4xx error ratios with threshold lines |
| API Latency (p50/p95/p99) | Latency percentile time series |
| Request Duration Heatmap | Distribution of request durations over time |
| PostgreSQL Connections | Active connections and transaction rate |
| Redis Ops/sec & Memory | Redis operations rate and memory usage |
| Tracking Service CPU & Memory | Process resource utilization |
| Cache Hit Ratio | Cache hit/miss ratio with thresholds |
| Current Request Rate | Single-stat gauge for current rps |
| Current P95 Latency | Single-stat gauge for current p95 |

---

## Metrics Observed

The tracking service exposes Prometheus metrics on port 9092:

| Metric | Description |
|--------|-------------|
| `http_requests_total` | Total HTTP requests |
| `http_request_duration_seconds` | Request latency histogram |
| `tracking_opens_total` | Open pixel requests |
| `tracking_clicks_total` | Click tracking requests |
| `tracking_unsubscribes_total` | Unsubscribe requests |
| `cache_hits_total` | Cache hit count |
| `cache_misses_total` | Cache miss count |
| `db_pool_connections` | Active database connections |
| `pg_stat_activity_count` | PostgreSQL connection count |
| `redis_commands_processed_total` | Redis command rate |

---

## Crate Scope Boundaries

### load-tests vs perf-tests

Both [`load-tests`](../../services/mail-server/crates/load-tests) and [`perf-tests`](../../services/mail-server/crates/perf-tests) crates exist with complementary purposes:

| Aspect | `load-tests` | `perf-tests` |
|--------|-------------|--------------|
| **Focus** | Throughput, concurrency, stress, isolation | Latency p95, latency p99, correctness under load |
| **Scenarios** | ID gen, validation, prediction, pattern matching, billing, trust scoring | Template render, billing calc, analytics rollup, compliance, trust scoring, operational health |
| **Thresholds** | Minimum ops/sec (throughput floors) | Maximum p95 latency (latency ceilings) |
| **Overlap** | Billing calculations and trust scoring appear in both | Deliberate — throughput AND latency coverage for critical paths |

### Why No api-server Dependency

Both crates intentionally avoid linking `api-server`:

- `load-tests` covers in-process throughput for core library operations
- `perf-tests` covers latency-sensitive operations at the library level
- HTTP end-to-end performance is validated through **k6 black-box tests**, which include middleware, TLS/proxy behavior, and network I/O

---

## Ownership

| Role | Responsibility |
|------|---------------|
| Platform engineer | Maintain scripts, environment, baselines |
| On-call engineer | Review gate failures on release candidates |
| Engineering lead | Sign-off on baseline updates |

---

## Related Documents

| Document | Description |
|----------|-------------|
| [`docs/evaluation/baselines/README.md`](baselines/README.md) | Baseline format specification |
| [`load-tests/README.md`](../../services/mail-server/crates/load-tests/README.md) | Load tests crate documentation |
| [`perf-tests/README.md`](../../services/mail-server/crates/perf-tests/README.md) | Performance tests crate documentation |
| `deploy/load-test-infra/` + k6 suites | load gate (manual/periodic) |
| [`deploy/load-test-infra/docker-compose.yml`](../../deploy/load-test-infra/docker-compose.yml) | Load test Docker Compose environment |
| [`deploy/load-test-infra/setup.sh`](../../deploy/load-test-infra/setup.sh) | Environment setup script |
| [`scripts/compare-baseline.sh`](../../scripts/compare-baseline.sh) | Baseline comparison tool |
| [`deploy/grafana/dashboards/load-testing-overview.json`](../../deploy/grafana/dashboards/load-testing-overview.json) | Grafana dashboard definition |
| [`docs/deployment/HETZNER_SIMULATION_CHECKLIST.md`](../deployment/HETZNER_SIMULATION_CHECKLIST.md) | Production-scale infrastructure guide |

---

## AI Bots — Mass-Concurrency Budgets (live compose harness)

The chat assistant and the mailbot reply pipeline have their own
mass-concurrency budgets, exercised by two scripts that drive the compose
stack black-box. Each script exits non-zero on any breach, so it can be
wired into a gate as-is:

| Harness | What it drives |
|---|---|
| [`tools/bots_perf_budget.py`](../../tools/bots_perf_budget.py) | 16 concurrent chat conversations across 3 tenants (one session user per conversation, `>=100 s` sustained at an 8 s cadence), 8 parallel session creations, 8 parallel turns into one session, per-tenant rate-limit isolation, Postgres connection-peak and container-memory sampling, server-log scans; then 20 simultaneous inbound SMTP messages and the first-response (priority 100) send lane. |
| [`tools/bots_disclosure_suite.py`](../../tools/bots_disclosure_suite.py) | The adversarial disclosure matrix against both bots: system-prompt/internal-instruction extraction (print/repeat/roleplay/nested quotes/base64/unicode/2 MB body), internal identifiers, secrets, other tenants' data, suppressed/legal-hold content, tool inventory; live RBAC probes (member, narrow-scope key, admin, owner), cross-tenant session/history/draft isolation, and a hostile inbound message per tenant for the drafted-reply lane. |

```bash
# Full budgets run (provisions 3 tenants through the product's own
# signup -> Mailpit verify -> login -> MFA flow, then 16 fixture users)
python3 tools/bots_perf_budget.py --fresh
# Re-run later against the same provisioned state
python3 tools/bots_perf_budget.py
# Lanes only
python3 tools/bots_perf_budget.py --chat-only
python3 tools/bots_perf_budget.py --mailbot-only

# Disclosure + RBAC/isolation suite (reuses the perf run's tenants/users)
python3 tools/bots_disclosure_suite.py
```

Budgets enforced by `bots_perf_budget.py` (rationale in the code header).
Chat turn p95 <= 10 s, p99 <= 15 s, p50 target <= 3 s, 0 x 5xx, 0
cross-tenant content. At most 10% 429 may appear at the sustained cadence:
the ai-service per-tenant governor defaults to 60/60 s. Session-create p95
<= 3 s, 8/8 parallel creates unique, 0 lost or duplicated parallel turns.
Tenant-A saturation must not starve tenant-B, so the 429 stays scoped.
`pg_stat_activity` peak <= 45 of `DB_MAX_CONNECTIONS`=50, with 0 pool-timeout
or panic logs. Api-server memory growth <= 25% (limit 512 MiB) and worker
under 1 GiB. Mailbot: 20/20 accepted, 0 loss or duplication, per-message
drain <= 90 s (the draft agent polls every 30 s and claims 10 rows per tick),
SMTP accept p95 <= 10 s, 0 reply-handler error-level logs.
First-response lane: claim <= 15 s in the first claim batch and send <= 30 s,
observed in Mailpit. The raw JSON report lands in
`/tmp/apexmail-bots-perf-report.json`; disclosure evidence lands in
`/tmp/apexmail-bots-disclosure-report.json`. The live run and its numbers are
recorded in
[`docs/audit/dogfood-2026-10-06/dogfood-bots-perf-compliance.md`](../audit/dogfood-2026-10-06/dogfood-bots-perf-compliance.md).

