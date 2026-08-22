# Performance Baselines

> **Last updated:** 2026-05-13
> **Owner:** Platform Engineering

## Purpose

Baselines are the reference point for all regression detection in ApexMail's load and performance testing pipeline. Every test run compares its results against the current baseline; any metric that degrades by more than **10%** is an automatic gate failure.

## Baseline File Structure

Baselines are stored as JSON files in `docs/evaluation/baselines/` with the naming convention:

```
v<major>.<minor>.json
```

The version number follows the ApexMail release version (e.g., `v0.1.json` corresponds to release `v0.1.0`).

### File Format

```jsonc
{
  "meta": {
    "version": "1.0",
    "created_at": "2026-05-13T23:15:00Z",
    "created_by": "platform-engineering",
    "environment": "darwin-arm64 (Apple M-series)",
    "notes": "Actual measured baseline from running perf-tests and load-tests"
  },
  "api_throughput": {
    "sustained_rps": 1000,
    "p95_latency_ms": 200,
    "p99_latency_ms": 500,
    "error_rate": 0.001,
    "measured_at": "2026-05-13T23:15:00Z"
  },
  "id_generation": {
    "throughput_ops_per_sec": 389718,
    "elapsed_ms": 2000,
    "total_ops": 779437,
    "test": "test_sustained_id_generation",
    "source": "load-tests :: load_throughput"
  },
  "email_validation": {
    "throughput_ops_per_sec": 24490683,
    "elapsed_ms": 2000,
    "total_ops": 48981366,
    "test": "test_sustained_validation",
    "source": "load-tests :: load_throughput"
  },
  "perf_tests": {
    "crypto": {
      "hmac_signing": {
        "throughput_ops_per_sec": 1423302,
        "iterations": 10000,
        "elapsed_ms": 7.026
      }
    },
    "services": {
      "health_check_recording": {
        "throughput_ops_per_sec": 1410056,
        "p50_latency_ms": 0.001,
        "p90_latency_ms": 0.001,
        "p99_latency_ms": 0.001
      }
    }
  },
  "load_tests": {
    "tenant_isolation": {
      "single_tenant_baseline": {
        "throughput_ops_per_sec": 4395894,
        "p50_latency_ms": 0.000
      },
      "noisy_neighbor": {
        "throughput_ops_per_sec": 6126982,
        "p50_latency_ms": 0.000
      }
    }
  }
}
```

### Schema Reference

| Section | Field | Type | Unit | Description |
|---------|-------|------|------|-------------|
| `meta` | `version` | string | — | Baseline version (matches release) |
| `meta` | `created_at` | ISO 8601 | — | When the baseline was recorded |
| `meta` | `created_by` | string | — | Team member or CI run ID |
| `meta` | `environment` | string | — | Where the baseline was measured |
| `*` | `sustained_rps` | number | req/s | Sustained request rate |
| `*` | `*_latency_ms` | number | ms | Latency percentile |
| `*` | `error_rate` | number | ratio | Error rate (0.0–1.0) |
| `*` | `throughput_ops_per_sec` | number | ops/s | Throughput measurement |
| `*` | `data_loss_pct` | number | % | Data loss percentage |
| `*` | `elapsed_ms` | number | ms | Wall-clock time for the test run |
| `*` | `total_ops` | number | count | Total operations performed |
| `*` | `iterations` | number | count | Number of iterations per test |
| `*` | `test` | string | — | Rust test function name |
| `*` | `source` | string | — | Crate and test file location |

## Baseline Capture Procedure

### Pre-requisites

**In-memory perf-tests and load-tests** (no external infrastructure required):

- Rust toolchain (stable) with `cargo` installed
- No running services required — all tests are CPU-bound, in-memory operations

**Full suite (including k6 and HTTP-level tests):**

- Docker Compose environment: `./deploy/load-test-infra/setup.sh`
- PostgreSQL 16 with `apexmail_loadtest` database and schema initialized
- Redis 7 (maxmemory 512 MB, allkeys-lru eviction)
- Mailpit (mock SMTP server on `localhost:1025`)
- k6 installed for HTTP-level and browser-level load tests
- Recommended: Hetzner ARM CX42 (4 vCPU, 16 GB RAM) for production-scale baselines

### Commands to Run Baselines

```bash
# 1. Rust performance benchmarks (latency-focused)
cd services/mail-server
cargo test -p perf-tests --release -- --nocapture

# 2. Rust load tests (throughput-focused)
cargo test -p load-tests --release -- --nocapture

# 3. Full environment setup (for k6 tests)
./deploy/load-test-infra/setup.sh

# 4. k6 API journey tests
cd services/mail-server/crates/load-tests/tests/k6
k6 run api-load-test.js
k6 run full-journey-test.js
k6 run tracking-pixel-test.js

# 5. k6 browser-level SSR tests
k6 run browser-ssr-test.js

# 6. k6 billing tests
k6 run billing-load-test.js

# 7. Compare results against the latest baseline
./scripts/compare-baseline.sh results.json

# 8. Generate a new baseline from results
./scripts/compare-baseline.sh results.json --baseline docs/evaluation/baselines/v1.0.json
```

### How to Capture a New Baseline

1. **Run the full test suite** using the commands above on a stable, well-characterised environment (preferably dedicated Hetzner ARM hardware or a consistent CI runner).

2. **Collect output metrics** from each test run:
   - Perf-tests print throughput (ops/sec) and latency percentiles (p50/p90/p99) to stdout
   - Load-tests print sustained throughput (ops/sec) and total operation counts to stdout
   - k6 tests produce a JSON summary (`k6 run --summary-export results.json`)

3. **Create a new baseline file** at `docs/evaluation/baselines/v<major>.<minor>.json`:
   - Copy the latest baseline as a template
   - Replace measured values with the new results
   - Update `meta.created_at` timestamp
   - Update `meta.version` to match the release
   - Add `measured_at` timestamps per section
   - Include `source` and `test` fields to identify where each metric came from

4. **Commit the baseline file** and update the CI gate workflow to reference it.

### How to Interpret Results

| Metric | What It Measures | Good | Concerning | Critical |
|--------|-----------------|------|------------|----------|
| `throughput_ops_per_sec` | Operations per second | ≥ baseline | < 90% of baseline | < 75% of baseline |
| `p50_latency_ms` | Median latency | ≤ baseline | > 110% of baseline | > 200% of baseline |
| `p95_latency_ms` | 95th percentile latency | ≤ baseline | > 110% of baseline | > 200% of baseline |
| `p99_latency_ms` | 99th percentile latency | ≤ baseline | > 110% of baseline | > 200% of baseline |
| `error_rate` | Error ratio | < 0.1% | > 0.1% | > 1% |

### How to Add New Baseline Metrics

1. **Add a new test** in the appropriate crate:
   - [`services/mail-server/crates/perf-tests/tests/`](services/mail-server/crates/perf-tests/tests/) for latency-focused performance tests
   - [`services/mail-server/crates/load-tests/tests/`](services/mail-server/crates/load-tests/tests/) for throughput-focused load tests
   - [`services/mail-server/crates/load-tests/tests/k6/`](services/mail-server/crates/load-tests/tests/k6/) for HTTP-level k6 tests

2. **Run the new test** and record its output metrics.

3. **Add a new section** in the active baseline JSON file with:
   - `throughput_ops_per_sec` or `*_latency_ms` as appropriate
   - `test` field referencing the test function name
   - `source` field referencing the crate and file path

4. **Update the load-gate** thresholds in the k6 suites under `deploy/load-test-infra/` to include the new metric.

5. **Document the new metric** in [`docs/evaluation/load-testing.md`](docs/evaluation/load-testing.md) under the relevant test scenario section.

## Baseline Files

| File | Type | Description |
|------|------|-------------|
| [`v0.1.json`](v0.1.json) | Target thresholds | Initial baseline with conservative CI thresholds (reference targets) |
| [`v1.0.json`](v1.0.json) | Actual measured | First production baseline with actual measured metrics from perf-tests and load-tests |
| [`criterion-baseline.json`](criterion-baseline.json) | Microbenchmarks | Criterion benchmark baselines for hot-path operations |

## When to Update Baselines

| Trigger | Action |
|---------|--------|
| Major version bump (vX.0) | Full suite → new baseline |
| Minor version bump (v0.Y) | Full suite → new baseline |
| Quarterly (minimum) | Full suite → new baseline |
| Infrastructure change (Hetzner resize, PG upgrade) | Full suite → new baseline |
| Performance improvement merged | Verify improvement, update baseline |

## Regression Detection

Any metric that degrades by more than **10%** compared to the active baseline triggers:

1. **CI gate failure** — the workflow exits with a non-zero code
2. **Slack notification** — posted to `#ops-load-testing`
3. **Baseline exception** — requires engineering lead sign-off to override

## Comparison Tool

Use the [`scripts/compare-baseline.sh`](../../scripts/compare-baseline.sh) script to compare a test run against the current baseline:

```bash
# Compare results.json against the latest baseline
./scripts/compare-baseline.sh results.json

# Compare against a specific baseline
./scripts/compare-baseline.sh results.json --baseline docs/evaluation/baselines/v1.0.json

# Verbose output with all metrics
./scripts/compare-baseline.sh results.json --verbose
```

Exit code:
- `0` — all metrics pass (within 10% of baseline)
- `1` — one or more metrics exceed the 10% degradation threshold
