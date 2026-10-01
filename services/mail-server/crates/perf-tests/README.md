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

## Baseline integration (SM12 F9)

Every timed test wraps its inputs and outputs in `std::hint::black_box` (so
LLVM cannot delete the measured work) and prints one machine-readable metric
line in the exact shape `scripts/compare-baseline.sh` reads:

```text
PERF_METRIC {"id_generation":{"throughput_ops_per_sec":389718.0}}
```

Collect the lines into a results file (strip the `PERF_METRIC ` prefix, one
JSON object per line, or merge with `jq -s 'add'`) and run the script as the
regression gate:

```sh
cargo test -p perf-tests --release -- --nocapture 2>&1 \
  | grep '^PERF_METRIC ' | sed 's/^PERF_METRIC //' > results.json
jq -s 'add' results.json > merged.json
../../scripts/compare-baseline.sh merged.json
```

If `PERF_RESULTS_JSON` is set, the same object is also appended to that file
as one JSON line.

In release builds the tests additionally assert a floor of 10% of the
committed `docs/evaluation/baselines/v1.0.json` throughput (transcribed into
`tests/budget.rs::baseline_ops_per_sec` — keep the two in sync). Debug builds
only apply the load-scaled wall-clock budgets: debug throughput is 10–50×
below the release-mode baseline by construction, so a baseline gate there
would measure the compiler, not the code.

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
