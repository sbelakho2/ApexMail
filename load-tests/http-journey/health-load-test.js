// ApexMail Health API Load Test — k6 script
// Targets GET /v1/health/liveness and GET /v1/health/readiness
// with ramp-up stages: 10 → 50 → 100 concurrent users.
//
// Health endpoints are critical for orchestration (k8s probes, load balancer checks)
// and must remain fast under concurrent load.
//
// Thresholds:
//   - p95 http_req_duration < 500ms (stricter target: < 200ms for health checks)
//   - p99 http_req_duration < 1000ms
//   - Error rate < 1%
//
// Usage:
//   k6 run health-load-test.js
//   K6_API_BASE=http://staging.apexmail.ee k6 run health-load-test.js

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// ── Custom metrics ───────────────────────────────────────────────────────────
const livenessDuration = new Trend('liveness_duration');
const readinessDuration = new Trend('readiness_duration');
const errorRate = new Rate('error_rate');
const totalRequests = new Counter('total_requests');

// ── Configuration ────────────────────────────────────────────────────────────
const API_BASE = __ENV.K6_API_BASE || 'http://localhost:3000';

// ── Options ──────────────────────────────────────────────────────────────────
export const options = {
  stages: [
    { duration: '1m', target: 10 },   // Quick ramp to 10 VUs
    { duration: '2m', target: 50 },   // Ramp to 50 VUs
    { duration: '3m', target: 100 },  // Ramp to 100 VUs
    { duration: '3m', target: 100 },  // Sustain at 100 VUs
    { duration: '1m', target: 0 },    // Rapid cool-down
  ],
  thresholds: {
    http_req_duration: ['p(95)<200', 'p(99)<500'],
    http_req_failed: ['rate<0.01'],
    liveness_duration: ['p(95)<200'],
    readiness_duration: ['p(95)<200'],
    error_rate: ['rate<0.001'],  // Health checks should virtually never fail
  },
  tags: {
    test: 'health-load',
    service: 'api-server',
  },
};

// ── Main test function ───────────────────────────────────────────────────────
export default function () {
  // ── Liveness check ────────────────────────────────────────────────────────
  group('Health Liveness', function () {
    const res = http.get(`${API_BASE}/v1/health/liveness`);

    livenessDuration.add(res.timings.duration);
    totalRequests.add(1);
    errorRate.add(res.status >= 400);

    check(res, {
      'liveness status is 200': (r) => r.status === 200,
      'liveness duration < 200ms': (r) => r.timings.duration < 200,
    });
  });

  // ── Readiness check ───────────────────────────────────────────────────────
  group('Health Readiness', function () {
    const res = http.get(`${API_BASE}/v1/health/readiness`);

    readinessDuration.add(res.timings.duration);
    totalRequests.add(1);
    errorRate.add(res.status >= 400);

    check(res, {
      'readiness status is 200': (r) => r.status === 200,
      'readiness duration < 200ms': (r) => r.timings.duration < 200,
    });
  });

  // ── Think time: minimal — health checks are called frequently ──
  sleep(Math.random() * 0.2 + 0.05); // 50–250ms between checks
}

// ── Teardown ─────────────────────────────────────────────────────────────────
export function teardown() {
  console.log(`Health load test complete. Total requests: ${totalRequests.name}`);
}
