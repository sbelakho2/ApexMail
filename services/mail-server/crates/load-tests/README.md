# load-tests

Load / stress tests for the ApexMail mail-server workspace.

## Running

```sh
# Run all load tests
cargo test -p load-tests --release -- --nocapture

# Run a specific test
cargo test -p load-tests --release -- test_sustained_id_generation --nocapture
```

## CI Thresholds

The load suite contains assertions, not just benchmark printouts. A run fails if
any of these floor thresholds are missed on the CI runner.

### Shared-Runner Thresholds (CI Gate)

Conservative minimums that must pass on standard GitHub Actions runners:

| Scenario | Minimum throughput |
| --- | ---: |
| ID generation | 10,000 ops/sec |
| Email validation | 50,000 ops/sec |
| Prediction scoring | 5,000 ops/sec |
| Pattern matching | 10,000 ops/sec |
| Billing calculations | 50,000 ops/sec |
| Trust scoring | 50,000 ops/sec |

### Production-Scale Targets

Target thresholds for dedicated Hetzner ARM infrastructure (4 vCPU, 16 GB RAM):

| Scenario | Production target |
| --- | ---: |
| ID generation | 100,000 ops/sec |
| Email validation | 500,000 ops/sec |
| Prediction scoring | 50,000 ops/sec |
| Pattern matching | 100,000 ops/sec |
| Billing calculations | 500,000 ops/sec |
| Trust scoring | 500,000 ops/sec |

Production targets are aspirational and should be validated on the dedicated
load-test environment (`deploy/load-test-infra/`). Raise shared-runner thresholds
only after multiple green baseline runs on production-scale hardware.

## Dependency Scope

`load-tests` intentionally covers in-process throughput for ID generation,
validation, prediction, pattern matching, billing, and trust scoring. It does
**not** link `api-server` for HTTP journey coverage; API-level load belongs in
external black-box tests (k6 scripts in `tests/k6/`) where middleware, TLS/proxy
behavior, and network I/O are included.

### Relationship with `perf-tests`

| Aspect | `load-tests` (this crate) | `perf-tests` |
|--------|---------------------------|--------------|
| **Focus** | Throughput (ops/sec), concurrency, stress, isolation | Latency (p95/p99), correctness under load |
| **Thresholds** | Minimum ops/sec (floors) | Maximum p95 latency (ceilings) |
| **Overlap** | Billing calculations and trust scoring appear in both | Deliberate — throughput AND latency coverage for critical paths |

Both crates avoid broad dependencies that are not directly exercised so
unused-dependency CI stays meaningful.
