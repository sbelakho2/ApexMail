# ApexMail Load Tests

This directory contains k6 performance and load test scripts for the ApexMail API.

## Directory Structure

```
load-tests/
├── baselines/            # Performance baseline data (with confidence intervals)
│   └── v1.0.json         # Baseline metrics: mean, std, sample_size, p95, p99
├── http/                 # HTTP-level load tests
│   ├── load-test.js      # Main load test (LT-C-01)
│   ├── spike-test.js     # Spike test (LT-C-02)
│   ├── smoke-test.js     # Smoke/validation test
│   ├── stress-test.js    # Stress test
│   └── test-options.js   # Shared options, headers, thresholds
├── http-journey/         # Multi-step journey tests
│   ├── combined-journey-test.js  # Combined journey (health + auth + email send)
│   ├── auth-load-test.js         # Auth-specific load test
│   ├── email-send-load-test.js   # Email send-specific load test
│   ├── health-load-test.js       # Health check load test
│   ├── tracking-pixel-test.js    # Tracking pixel test
│   └── README.md                  # Journey test documentation
└── README.md             # This file
```

## Running Tests

```bash
# Main load test
k6 run load-tests/http/load-test.js

# Spike test
k6 run load-tests/http/spike-test.js

# With custom API base
K6_API_BASE=http://staging.apexmail.ee k6 run load-tests/http/load-test.js
```

## Prometheus Metrics Integration (M-DATA-10)

To push k6 metrics to Prometheus / VictoriaMetrics for correlation with production performance trends:

```bash
# Using k6's Prometheus remote write output
k6 run \
  --out output-prometheus-remote \
  http/load-test.js
```

Configure the Prometheus remote write endpoint via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `K6_PROMETHEUS_REMOTE_URL` | `http://localhost:9090/api/v1/write` | Remote write endpoint |
| `K6_PROMETHEUS_REMOTE_USER` | — | Basic auth username |
| `K6_PROMETHEUS_REMOTE_PASSWORD` | — | Basic auth password |
| `K6_PROMETHEUS_HEADERS` | — | Additional HTTP headers |

Tags applied automatically:
- `test_name`: The test script name (e.g., `load-test`, `spike-test`)
- `environment`: From `K6_ENV` or `staging`
- `ci_run`: CI run ID if available

This enables:
- Comparing CI load test results against production trends
- Detecting regressions before deployment
- Capacity planning and trend analysis
- Correlating load test results with system metrics

## Baseline Comparisons

After running a test, compare results against baselines:

```bash
# Check if current run meets baseline thresholds
k6 run --summary-export=current.json load-tests/http/load-test.js
./scripts/compare-baseline.sh current.json --baseline load-tests/baselines/v1.0.json
```

Baseline files include confidence intervals (`mean`, `std`, `sample_size`) for statistical significance testing.
