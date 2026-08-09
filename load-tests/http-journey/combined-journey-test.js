// ApexMail Combined HTTP Journey Load Test — k6 script
// Exercises all 4 critical API paths with realistic traffic distribution:
//   1. GET  /health/live   — Health liveness check  (10%)
//   2. GET  /health/ready  — Health readiness check  (10%)
//   3. POST /v1/auth/login        — Authentication          (30%)
//   4. POST /v1/messages        — Email sending           (50%)
//
// Ramp-up stages: 10 → 50 → 100 concurrent users.
//
// Thresholds:
//   - p95 http_req_duration < 500ms
//   - p99 http_req_duration < 1000ms
//   - Error rate < 1%
//   - Per-endpoint p95 thresholds for visibility
//
// Usage:
//   k6 run combined-journey-test.js
//   K6_API_BASE=http://staging.apexmail.ee K6_API_KEY=xxx k6 run combined-journey-test.js

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// ── Custom metrics ───────────────────────────────────────────────────────────
const authLoginDuration = new Trend('auth_login_duration');
const emailSendDuration = new Trend('email_send_duration');
const livenessDuration = new Trend('liveness_duration');
const readinessDuration = new Trend('readiness_duration');
const errorRate = new Rate('error_rate');
const totalRequests = new Counter('total_requests');

// ── Configuration ────────────────────────────────────────────────────────────
const API_BASE = __ENV.K6_API_BASE || 'http://localhost:3000';
const API_KEY = __ENV.K6_API_KEY || 'test-api-key-00000000000000000000000000000';

const JSON_HEADERS = {
  'Content-Type': 'application/json',
};

const AUTH_HEADERS = {
  'Authorization': `Bearer ${API_KEY}`,
  'Content-Type': 'application/json',
  'X-Tenant-ID': `tenant-${__VU}`,
};

// ── Options ──────────────────────────────────────────────────────────────────
export const options = {
  stages: [
    { duration: '2m', target: 10 },   // Warm-up to 10 VUs
    { duration: '3m', target: 50 },   // Ramp to 50 VUs
    { duration: '3m', target: 100 },  // Ramp to 100 VUs
    { duration: '5m', target: 100 },  // Sustain at 100 VUs
    { duration: '2m', target: 0 },    // Cool-down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1000'],
    http_req_failed: ['rate<0.01'],
    auth_login_duration: ['p(95)<500'],
    email_send_duration: ['p(95)<500'],
    liveness_duration: ['p(95)<200'],
    readiness_duration: ['p(95)<200'],
    error_rate: ['rate<0.01'],
  },
  tags: {
    test: 'combined-journey',
    service: 'api-server',
  },
};

// ── Helpers ──────────────────────────────────────────────────────────────────
function randomEmail() {
  const domains = ['example.com', 'test.org', 'demo.net', 'mail.loc'];
  return `test-${__VU}-${Date.now()}@${domains[Math.floor(Math.random() * domains.length)]}`;
}

function loginPayload() {
  return JSON.stringify({
    email: `user-${__VU}@apexmail.ee`,
    password: 'test-password',
  });
}

function emailPayload() {
  return JSON.stringify({
    to: [randomEmail()],
    from: `sender-${__VU}@apexmail.ee`,
    subject: `Journey Test Email — VU ${__VU} — ${Date.now()}`,
    text_body: `Journey test email body. VU=${__VU}`,
    html_body: `<html><body><p>Journey test</p><p>VU=${__VU}</p></body></html>`,
    tags: { journey_test: 'true', vu: String(__VU) },
    options: {
      track_opens: false,
      track_clicks: false,
      priority: 'normal',
    },
  });
}

// ── Flow 1: Auth Login ──────────────────────────────────────────────────────
function flowAuthLogin() {
  group('Auth Login', function () {
    const payload = loginPayload();
    const res = http.post(`${API_BASE}/v1/auth/login`, payload, {
      headers: JSON_HEADERS,
      tags: { flow: 'auth', action: 'login' },
    });
    authLoginDuration.add(res.timings.duration);
    totalRequests.add(1);
    errorRate.add(res.status >= 400);
    check(res, {
      'auth login status is 200': (r) => r.status === 200,
      'auth login has token': (r) => {
        try { return JSON.parse(r.body).token !== undefined; }
        catch { return false; }
      },
    });
  });
}

// ── Flow 2: Email Send ──────────────────────────────────────────────────────
function flowEmailSend() {
  group('Email Send', function () {
    const payload = emailPayload();
    const res = http.post(`${API_BASE}/v1/messages`, payload, {
      headers: AUTH_HEADERS,
      tags: { flow: 'email', action: 'send' },
    });
    emailSendDuration.add(res.timings.duration);
    totalRequests.add(1);
    errorRate.add(res.status >= 400);
    check(res, {
      'email send status is 202': (r) => r.status === 202,
      'email send has message_id': (r) => {
        try { return JSON.parse(r.body).message_id !== undefined; }
        catch { return false; }
      },
    });
  });
}

// ── Flow 3: Health Liveness ─────────────────────────────────────────────────
function flowLiveness() {
  group('Health Liveness', function () {
    const res = http.get(`${API_BASE}/health/live`, {
      tags: { flow: 'health', action: 'liveness' },
    });
    livenessDuration.add(res.timings.duration);
    totalRequests.add(1);
    errorRate.add(res.status >= 400);
    check(res, {
      'liveness status is 200': (r) => r.status === 200,
    });
  });
}

// ── Flow 4: Health Readiness ────────────────────────────────────────────────
function flowReadiness() {
  group('Health Readiness', function () {
    const res = http.get(`${API_BASE}/health/ready`, {
      tags: { flow: 'health', action: 'readiness' },
    });
    readinessDuration.add(res.timings.duration);
    totalRequests.add(1);
    errorRate.add(res.status >= 400);
    check(res, {
      'readiness status is 200': (r) => r.status === 200,
    });
  });
}

// ── Main test function ───────────────────────────────────────────────────────
export default function () {
  // Traffic distribution:
  //   10% Liveness, 10% Readiness, 30% Auth Login, 50% Email Send
  //
  // Health endpoints are naturally called frequently by orchestrators.
  // Auth and Email Send represent real user traffic.
  const roll = Math.random();

  if (roll < 0.10) {
    flowLiveness();
  } else if (roll < 0.20) {
    flowReadiness();
  } else if (roll < 0.50) {
    flowAuthLogin();
  } else {
    flowEmailSend();
  }

  // ── Think time: simulate real user behavior ──
  // Varies by endpoint — health checks poll more frequently
  if (roll < 0.20) {
    sleep(Math.random() * 0.2 + 0.05);   // 50–250ms for health checks
  } else {
    sleep(Math.random() * 0.5 + 0.1);    // 100–600ms for user-facing endpoints
  }
}

// ── Setup ────────────────────────────────────────────────────────────────────
export function setup() {
  console.log('Combined HTTP journey load test starting...');
  console.log(`API Base: ${API_BASE}`);
  return { start_time: Date.now() };
}

// ── Teardown ─────────────────────────────────────────────────────────────────
export function teardown() {
  console.log(`Combined journey load test complete. Total requests: ${totalRequests.name}`);
}
