// ApexMail Email Send API Load Test — k6 script
// Targets POST /v1/messages with ramp-up stages: 10 → 50 → 100 concurrent users.
//
// Real API contract (services/mail-server/crates/api-server):
//   * Auth: `X-API-Key: am_…` (middleware/auth.rs) — NOT Authorization: Bearer.
//   * Body: SendMessageRequest is deny_unknown_fields and accepts
//     {from, to[], subject, html?, text?, tags?: string[]} — html_body/
//     text_body/tags-as-object are a guaranteed 422.
//   * Response: 202 {"data":{"id","status","created_at"},"error":null}.
//
// Thresholds:
//   - p95 http_req_duration < 500ms
//   - p99 http_req_duration < 1000ms
//   - Error rate < 1%
//
// Run (manual/on-demand — the load-gate workflow is archived, ci/README.md §2):
//   K6_API_KEY=am_live_… K6_API_BASE=http://localhost:8080 \
//     K6_FROM_EMAIL=sender@verified.example \
//     k6 run email-send-load-test.js

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// ── Custom metrics ───────────────────────────────────────────────────────────
const emailSendDuration = new Trend('email_send_duration');
const errorRate = new Rate('error_rate');
const totalRequests = new Counter('total_requests');

// ── Configuration ────────────────────────────────────────────────────────────
const API_BASE = __ENV.K6_API_BASE || 'http://localhost:3000';
const API_KEY = __ENV.K6_API_KEY || '';
const FROM_EMAIL = __ENV.K6_FROM_EMAIL || 'loadtest@example.com';

const AUTH_HEADERS = {
  'X-API-Key': API_KEY,
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
    email_send_duration: ['p(95)<500'],
    error_rate: ['rate<0.01'],
  },
  tags: {
    test: 'email-send-load',
    endpoint: 'v1-messages',
    service: 'api-server',
  },
};

// ── Setup ────────────────────────────────────────────────────────────────────
export function setup() {
  if (!API_KEY) {
    throw new Error(
      'K6_API_KEY is required (X-API-Key: am_… for the target tenant); ' +
        'POST /v1/messages rejects every request without it'
    );
  }
  return { start_time: Date.now() };
}

// ── Helper: Generate test payloads ───────────────────────────────────────────
function randomEmail() {
  const domains = ['example.com', 'test.org', 'demo.net', 'mail.loc'];
  return `test-${__VU}-${Date.now()}@${domains[Math.floor(Math.random() * domains.length)]}`;
}

function emailPayload() {
  return JSON.stringify({
    from: FROM_EMAIL,
    to: [randomEmail()],
    subject: `Email Send Load Test — VU ${__VU} — ${Date.now()}`,
    text: `Load test email body. VU=${__VU}, time=${Date.now()}`,
    html: `<html><body><p>Load test email</p><p>VU=${__VU}</p></body></html>`,
    tags: ['email-send-load'],
  });
}

// ── Main test function ───────────────────────────────────────────────────────
export default function () {
  group('Email Send', function () {
    const url = `${API_BASE}/v1/messages`;
    const payload = emailPayload();
    const res = http.post(url, payload, { headers: AUTH_HEADERS });

    emailSendDuration.add(res.timings.duration);
    totalRequests.add(1);
    errorRate.add(res.status >= 400);

    check(res, {
      'email send status is 202': (r) => r.status === 202,
      'email send returns the queued message envelope': (r) => {
        try { return JSON.parse(r.body).data.id !== undefined; }
        catch { return false; }
      },
      'email send duration < 500ms': (r) => r.timings.duration < 500,
    });
  });

  // ── Think time: simulate real user behavior ──
  sleep(Math.random() * 0.5 + 0.1); // 100–600ms between requests
}
