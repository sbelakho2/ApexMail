// ApexMail Combined HTTP Journey Load Test — k6 script
// Exercises the critical API paths with realistic traffic distribution:
//   1. GET  /health/live         — Health liveness check    (10%)
//   2. GET  /health/ready        — Health readiness check   (10%)
//   3. GET  /v1/messages?limit=1 — Authenticated read probe  (30%)
//   4. POST /v1/messages         — Email sending            (50%)
//
// Authentication is the documented non-interactive path: `X-API-Key: am_…`
// (middleware/auth.rs). POST /v1/auth/login is a CSRF-gated session flow and
// is NOT part of this journey (see auth-load-test.js for that flow).
//
// Ramp-up stages: 10 → 50 → 100 concurrent users.
//
// Thresholds:
//   - p95 http_req_duration < 500ms
//   - p99 http_req_duration < 1000ms
//   - Error rate < 1%
//   - Per-endpoint p95 thresholds for visibility
//
// Run (manual/on-demand — the load-gate workflow is archived, ci/README.md §2):
//   K6_API_KEY=am_live_… K6_API_BASE=http://localhost:8080 \
//     K6_FROM_EMAIL=sender@verified.example \
//     k6 run combined-journey-test.js

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// ── Custom metrics ───────────────────────────────────────────────────────────
const authProbeDuration = new Trend('auth_probe_duration');
const emailSendDuration = new Trend('email_send_duration');
const livenessDuration = new Trend('liveness_duration');
const readinessDuration = new Trend('readiness_duration');
const errorRate = new Rate('error_rate');
const totalRequests = new Counter('total_requests');

// ── Configuration ────────────────────────────────────────────────────────────
const API_BASE = __ENV.K6_API_BASE || 'http://localhost:3000';
const API_KEY = __ENV.K6_API_KEY || '';
const FROM_EMAIL = __ENV.K6_FROM_EMAIL || 'loadtest@example.com';

const JSON_HEADERS = {
  'Content-Type': 'application/json',
};

// The API key header the api-server actually reads (NOT Authorization: Bearer).
const AUTH_HEADERS = {
  'X-API-Key': API_KEY,
  'Content-Type': 'application/json',
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
    auth_probe_duration: ['p(95)<500'],
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

// ── Setup ────────────────────────────────────────────────────────────────────
export function setup() {
  if (!API_KEY) {
    throw new Error(
      'K6_API_KEY is required (X-API-Key: am_… for the target tenant); ' +
        'the journey cannot authenticate without it'
    );
  }
  console.log(`Combined journey: base=${API_BASE} from=${FROM_EMAIL}`);
  return { start_time: Date.now() };
}

// ── Helpers ──────────────────────────────────────────────────────────────────
function randomEmail() {
  const domains = ['example.com', 'test.org', 'demo.net', 'mail.loc'];
  return `test-${__VU}-${Date.now()}@${domains[Math.floor(Math.random() * domains.length)]}`;
}

function emailPayload() {
  // Real SendMessageRequest shape: html/text, tags as string[].
  return JSON.stringify({
    from: FROM_EMAIL,
    to: [randomEmail()],
    subject: `Journey Test Email — VU ${__VU} — ${Date.now()}`,
    text: `Journey test email body. VU=${__VU}`,
    html: `<html><body><p>Journey test</p><p>VU=${__VU}</p></body></html>`,
    tags: ['journey-test'],
  });
}

// ── Flow 1: Authenticated read probe ─────────────────────────────────────────
function flowAuthProbe() {
  group('Auth Probe', function () {
    const res = http.get(`${API_BASE}/v1/messages?limit=1`, {
      headers: AUTH_HEADERS,
      tags: { flow: 'auth', action: 'probe' },
    });
    authProbeDuration.add(res.timings.duration);
    totalRequests.add(1);
    errorRate.add(res.status >= 400);
    check(res, {
      'auth probe status is 200': (r) => r.status === 200,
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
      'email send returns the queued message envelope': (r) => {
        try { return JSON.parse(r.body).data.id !== undefined; }
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
  //   10% Liveness, 10% Readiness, 30% Auth probe, 50% Email Send
  const roll = Math.random();

  if (roll < 0.10) {
    flowLiveness();
  } else if (roll < 0.20) {
    flowReadiness();
  } else if (roll < 0.50) {
    flowAuthProbe();
  } else {
    flowEmailSend();
  }

  // Think time varies by endpoint — health checks poll more frequently.
  if (roll < 0.20) {
    sleep(Math.random() * 0.2 + 0.05);   // 50–250ms for health checks
  } else {
    sleep(Math.random() * 0.5 + 0.1);    // 100–600ms for user-facing endpoints
  }
}

// ── Teardown ─────────────────────────────────────────────────────────────────
export function teardown() {
  console.log('Combined journey load test complete.');
}
