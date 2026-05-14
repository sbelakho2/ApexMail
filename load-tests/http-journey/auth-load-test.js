// ApexMail Auth API Load Test — k6 script
// Targets POST /v1/auth/login with ramp-up stages: 10 → 50 → 100 concurrent users.
//
// Thresholds:
//   - p95 http_req_duration < 500ms
//   - p99 http_req_duration < 1000ms
//   - Error rate < 1%
//
// Usage:
//   k6 run auth-load-test.js
//   K6_API_BASE=http://staging.apexmail.ee k6 run auth-load-test.js

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// ── Custom metrics ───────────────────────────────────────────────────────────
const authLoginDuration = new Trend('auth_login_duration');
const errorRate = new Rate('error_rate');
const totalRequests = new Counter('total_requests');

// ── Configuration ────────────────────────────────────────────────────────────
const API_BASE = __ENV.K6_API_BASE || 'http://localhost:3000';

const HEADERS = {
  'Content-Type': 'application/json',
};

// ── Options ──────────────────────────────────────────────────────────────────
export const options = {
  stages: [
    { duration: '2m', target: 10 },   // Ramp-up to 10 VUs
    { duration: '3m', target: 50 },   // Ramp-up to 50 VUs
    { duration: '3m', target: 100 },  // Ramp-up to 100 VUs
    { duration: '5m', target: 100 },  // Sustain at 100 VUs
    { duration: '2m', target: 0 },    // Ramp-down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1000'],
    http_req_failed: ['rate<0.01'],
    auth_login_duration: ['p(95)<500'],
    error_rate: ['rate<0.01'],
  },
  tags: {
    test: 'auth-load',
    endpoint: 'v1-auth-login',
    service: 'api-server',
  },
};

// ── Helper: Generate login payload ──────────────────────────────────────────
function loginPayload() {
  return JSON.stringify({
    email: `user-${__VU}@apexmail.ee`,
    password: 'test-password',
  });
}

// ── Main test function ───────────────────────────────────────────────────────
export default function () {
  group('Auth Login', function () {
    const url = `${API_BASE}/v1/auth/login`;
    const payload = loginPayload();
    const res = http.post(url, payload, { headers: HEADERS });

    authLoginDuration.add(res.timings.duration);
    totalRequests.add(1);
    errorRate.add(res.status >= 400);

    check(res, {
      'auth login status is 200': (r) => r.status === 200,
      'auth login has token': (r) => {
        try { return JSON.parse(r.body).token !== undefined; }
        catch { return false; }
      },
      'auth login duration < 500ms': (r) => r.timings.duration < 500,
    });
  });

  // ── Think time: simulate real user behavior ──
  sleep(Math.random() * 0.5 + 0.1); // 100–600ms between requests
}

// ── Teardown ─────────────────────────────────────────────────────────────────
export function teardown() {
  console.log(`Auth load test complete. Total requests: ${totalRequests.name}`);
}
