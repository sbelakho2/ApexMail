# Load Testing Strategy

> Internal document — Bel Consulting OÜ

## Overview

This document defines the load-testing strategy for ApexMail. Every release that touches the API, worker, MTA, or tracking hot-paths **must** pass the gate tests described here before promotion to production.

---

## Tooling

| Tool | Purpose |
|------|---------|
| **k6** (Grafana) | Primary load generator — scriptable in JS, Prometheus-native output |
| **k6-operator** | Run distributed tests from multiple Hetzner regions when single-machine throughput is insufficient |
| **Prometheus + Grafana** | Real-time observation during test runs (dedicated `load-test` dashboard) |

All test scripts live in `tools/load-tests/` and are version-controlled alongside application code.

### k6 Configuration Defaults

```javascript
export const options = {
  thresholds: {
    http_req_duration: ['p(95)<200', 'p(99)<500'],
    http_req_failed:   ['rate<0.001'],
  },
  scenarios: { /* per-test */ },
};
```

---

## Test Scenarios

### 1. API Throughput

Exercises the Hono API server under sustained load.

| Parameter | Target |
|-----------|--------|
| Virtual users | Ramp 0 → 500 → 1 000 over 5 min, hold 10 min |
| Request rate | 1 000 rps sustained |
| p95 latency | < 200 ms |
| p99 latency | < 500 ms |
| Error rate | < 0.1 % |

**Endpoints under test:**

- `POST /api/v1/contacts` — contact creation
- `POST /api/v1/campaigns/:id/send` — campaign trigger
- `GET  /api/v1/campaigns` — list with pagination
- `GET  /api/v1/analytics/overview` — analytics aggregation
- `POST /api/v1/webhooks/inbound` — inbound webhook ingestion

### 2. Email Sending Pipeline

End-to-end: API → queue → worker → MTA.

| Parameter | Target |
|-----------|--------|
| Injection rate | 5 000 messages / second |
| Queue processing latency | < 10 s from enqueue to MTA hand-off |
| Worker error rate | < 0.01 % |
| MTA connection pool utilisation | < 80 % |

Seed the database with 1 M contacts split across 50 tenants before running.

### 3. Webhook Delivery

Simulates outbound webhook dispatching at scale.

| Parameter | Target |
|-----------|--------|
| Concurrent deliveries | 2 000 |
| Delivery p95 | < 2 s (includes DNS + TLS to mock endpoint) |
| Retry storm | Inject 50 % 5xx from mock; confirm back-off and no queue starvation |

### 4. Concurrent Users — Control Plane & Web

Browser-level load for the Next.js control-plane and marketing site.

| Parameter | Target |
|-----------|--------|
| Concurrent sessions | 500 |
| Page load p95 | < 1.5 s (nginx cache warm) |
| SSR render p95 | < 400 ms |

### 5. Tracking Pixel & Click Tracking

High-volume GET requests through the tracking service.

| Parameter | Target |
|-----------|--------|
| Request rate | 10 000 rps |
| p95 latency | < 50 ms |
| Data loss | 0 — every event must reach the analytics pipeline |

---

## Environment Setup

1. **Dedicated load-test server** — Hetzner Cloud ARM server in the same region as staging.
2. **Isolated database** — Separate PostgreSQL instance restored from anonymised staging snapshot.
3. **Redis** — Dedicated instance; flush before each run.
4. **MTA sink** — Local SMTP sink (e.g. `smtp-sink` from Postfix) to avoid real deliveries.
5. **Mock webhook receiver** — Express server logging requests with configurable failure rates.

```bash
# Spin up the environment
cd tools/load-tests
./setup-env.sh          # provisions via hcloud CLI
k6 run scenarios/api-throughput.js --out prometheus
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

Integrated into CI via a dedicated GitHub Actions workflow:

```yaml
# .github/workflows/load-test.yml (excerpt)
jobs:
  load-gate:
    runs-on: self-hosted          # Hetzner runner
    steps:
      - uses: grafana/k6-action@v0.3
        with:
          filename: tools/load-tests/scenarios/api-throughput.js
          flags: --out json=results.json
      - run: node tools/load-tests/compare-baseline.js results.json
```

`compare-baseline.js` exits non-zero when any threshold breaches the 10 % regression window.

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
- Worker queue depth & processing latency
- PostgreSQL active connections & query duration
- Redis ops/sec & memory usage
- MTA throughput & connection pool

---

## Reporting

After every full-suite run, generate a Markdown report:

```bash
node tools/load-tests/generate-report.js results/ > docs/evaluation/reports/$(date +%F).md
```

Include: scenario, pass/fail, key metrics vs baseline, Grafana snapshot link, and any anomalies.

---

## Ownership

| Role | Responsibility |
|------|---------------|
| Platform engineer | Maintain scripts, environment, baselines |
| On-call engineer | Review gate failures on release candidates |
| Engineering lead | Sign-off on baseline updates |

---

*Last updated: 2026-02-09*
