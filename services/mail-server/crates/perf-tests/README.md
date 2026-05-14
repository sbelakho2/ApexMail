# perf-tests

Performance / benchmark tests for the ApexMail mail-server workspace.

## Running

```sh
# Run all performance tests
cargo test -p perf-tests --release -- --nocapture

# Run a specific test
cargo test -p perf-tests --release -- perf_template_render --nocapture
```

## CI Thresholds

The performance suite is expected to fail when core service behavior regresses
past these conservative shared-runner thresholds:

| Scenario | Shared-runner threshold | Production target |
| --- | ---: | ---: |
| Template render p95 | < 500 ms | < 100 ms |
| Billing calculation p95 | < 250 ms | < 50 ms |
| Analytics rollup p95 | < 500 ms | < 100 ms |
| Compliance policy evaluation p95 | < 500 ms | < 100 ms |
| Trust scoring throughput | >= 25,000 ops/sec | >= 250,000 ops/sec |
| Operational health aggregation p95 | < 250 ms | < 50 ms |

Shared-runner thresholds are conservative enough for standard CI runners.
Production targets are for dedicated Hetzner ARM infrastructure.

Threshold changes require a baseline run and an accompanying note in this file.

## Dependency Scope

`perf-tests` is the cross-crate performance harness for core library behavior:
database helpers, billing, AI scoring, template rendering, analytics,
compliance, and operational services. It does not link `api-server` because
HTTP end-to-end performance is validated through deployment-level load tests
(k6 scripts in `load-tests/tests/k6/`), not unit-test binaries.

### Relationship with `load-tests`

| Aspect | `perf-tests` (this crate) | `load-tests` |
|--------|---------------------------|--------------|
| **Focus** | Latency (p95/p99), correctness under load | Throughput (ops/sec), concurrency, stress, isolation |
| **Thresholds** | Maximum p95 latency (ceilings) | Minimum ops/sec (floors) |
| **Overlap** | Billing and trust scoring appear in both | Deliberate — throughput AND latency coverage |

Keep dependencies limited to crates with exercised code; CI runs unused-dependency
detection to prevent benchmark-only crates from becoming dependency catch-alls.
