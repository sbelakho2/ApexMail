# Load Testing Strategy

> Internal document — Bel Consulting OÜ
>
> **Implementation Note (2026-02):** Load tests have been migrated to Rust and are located in `services/mail-server/crates/load-tests/`.

## Overview

This document defines the load-testing strategy for ApexMail. Every release that touches the tracking service hot-paths **must** pass the gate tests described here before promotion to production.

---

## Tooling

| Tool | Purpose |
|------|---------|
| **Rust load-tests crate** | Primary load generator — native Rust with async/await |
| **Criterion** | Microbenchmarks for hot paths |
| **Prometheus + Grafana** | Real-time observation during test runs (dedicated `load-test` dashboard) |

All test scripts live in `services/mail-server/crates/load-tests/` and are version-controlled alongside application code.

### Running Load Tests

```bash
cd services/mail-server

# Run all load tests
cargo test -p load-tests --release

# Run specific benchmark
cargo bench -p load-tests
```

---

## Test Scenarios

### 1. API Throughput

Exercises the Rust tracking service under sustained load.

| Parameter | Target |
|-----------|--------|
| Virtual users | Ramp 0 → 500 → 1 000 over 5 min, hold 10 min |
| Request rate | 1 000 rps sustained |
| p95 latency | < 200 ms |
| p99 latency | < 500 ms |
| Error rate | < 0.1 % |

**Endpoints under test:**

- `POST /v1/messages` — message sending
- `GET /v1/messages` — list with pagination
- `GET /health` — health check
- `GET /ready` — readiness check

### 2. Tracking Pixel & Click Tracking

High-volume GET requests through the tracking service.

| Parameter | Target |
|-----------|--------|
| Request rate | 10 000 rps |
| p95 latency | < 50 ms |
| Data loss | 0 — every event must reach the database |

**Endpoints under test:**

- `GET /t/{tracking_id}` — open pixel
- `GET /c/{tracking_id}` — click redirect
- `POST /u/{token}` — unsubscribe

### 3. Concurrent Users — SSR Browser Surfaces

Browser-level load for the Rust-served `control-plane` and `web` surfaces behind nginx.

| Parameter | Target |
|-----------|--------|
| Concurrent sessions | 500 |
| Page load p95 | < 1.5 s (nginx cache warm) |
| SSR render p95 | < 400 ms |

---

## Environment Setup

1. **Dedicated load-test server** — Hetzner Cloud ARM server in the same region as staging.
2. **Isolated database** — Separate PostgreSQL instance restored from anonymised staging snapshot.
3. **Redis** — Dedicated instance; flush before each run.
4. **Mock SMTP** — Mailpit or smtp-sink for capturing emails without real delivery.

```bash
# Spin up infrastructure
docker compose up -d postgres redis

# Run load tests
cd services/mail-server
cargo test -p load-tests --release -- --nocapture
```

---

## Baseline Establishment

On every major version bump (or quarterly at minimum):

1. Run the full suite against a clean staging environment.
2. Record results in `docs/evaluation/baselines/vX.Y.json`.
3. Grafana snapshot URL stored alongside for visual reference.

Baselines are the **regression detection** reference. Any future run that degrades a key metric by more than **10 %** from baseline is an automatic gate failure.

---

## Regression Detection

Integrated into CI via GitHub Actions workflow:

```yaml
# .github/workflows/load-test.yml (excerpt)
jobs:
  load-gate:
    runs-on: self-hosted  # Hetzner runner
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: |
          cd services/mail-server
          cargo test -p load-tests --release -- --nocapture
```

### When to Run

| Trigger | Scenarios |
|---------|-----------|
| PR merge to `main` | API throughput (reduced: 2 min hold) |
| Release candidate tag | Full suite |
| Infrastructure change (Hetzner resize, PG upgrade) | Full suite |
| Quarterly schedule | Full suite + new baseline |

---

## Grafana Dashboard

Dashboard UID: `load-testing-overview`

Panels:

- Request rate & error rate (time series)
- Latency heatmap (p50 / p95 / p99)
- PostgreSQL active connections & query duration
- Redis ops/sec & memory usage
- Tracking service memory & CPU usage

---

## Metrics Observed

The tracking service exposes Prometheus metrics on port 9092:

| Metric | Description |
|--------|-------------|
| `http_requests_total` | Total HTTP requests |
| `http_request_duration_seconds` | Request latency histogram |
| `tracking_opens_total` | Open pixel requests |
| `tracking_clicks_total` | Click tracking requests |
| `db_pool_connections` | Active database connections |

---

## Ownership

| Role | Responsibility |
|------|---------------|
| Platform engineer | Maintain scripts, environment, baselines |
| On-call engineer | Review gate failures on release candidates |
| Engineering lead | Sign-off on baseline updates |

---

*Last updated: 2026-02-23*
