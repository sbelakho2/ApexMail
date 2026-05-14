// ApexMail Email Send API Load Test — k6 script
// Targets POST /v1/email/send with ramp-up stages: 10 → 50 → 100 concurrent users.
//
// Thresholds:
//   - p95 http_req_duration < 500ms
//   - p99 http_req_duration < 1000ms
//   - Error rate < 1%
//
// Usage:
//   k6 run email-send-load-test.js
//   K6_API_BASE=http://staging.apexmail.ee K6_API_KEY=xxx k6 run email-send-load-test.js

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// ── Custom metrics ───────────────────────────────────────────────────────────
const emailSendDuration = new Trend('email_send_duration');
const errorRate = new Rate('error_rate');
const totalRequests = new Counter('total_requests');

// ── Configuration ────────────────────────────────────────────────────────────
const API_BASE = __ENV.K6_API_BASE || 'http://localhost:3000';
const API_KEY = __ENV.K6_API_KEY || 'test-api-key-00000000000000000000000000000';

const AUTH_HEADERS = {
  'Authorization': `Bearer ${API_KEY}`,
  'Content-Type': 'application/json',
  'X-Tenant-ID': `tenant-${__VU}`,
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
    endpoint: 'v1-email-send',
    service: 'api-server',
  },
};

// ── Helper: Generate test payloads ───────────────────────────────────────────
function randomEmail() {
  const domains = ['example.com', 'test.org', 'demo.net', 'mail.loc'];
  return `test-${__VU}-${Date.now()}@${domains[Math.floor(Math.random() * domains.length)]}`;
}

function emailPayload() {
  return JSON.stringify({
    to: [randomEmail()],
    from: `sender-${__VU}@apexmail.ee`,
    subject: `Email Send Load Test — VU ${__VU} — ${Date.now()}`,
    text_body: `Load test email body. VU=${__VU}, time=${Date.now()}`,
    html_body: `<html><body><p>Load test email</p><p>VU=${__VU}</p></body></html>`,
    tags: { load_test: 'true', vu: String(__VU) },
    options: {
      track_opens: false,
      track_clicks: false,
      priority: 'normal',
    },
  });
}

// ── Main test function ───────────────────────────────────────────────────────
export default function () {
  group('Email Send', function () {
    const url = `${API_BASE}/v1/email/send`;
    const payload = emailPayload();
    const res = http.post(url, payload, { headers: AUTH_HEADERS });

    emailSendDuration.add(res.timings.duration);
    totalRequests.add(1);
    errorRate.add(res.status >= 400);

    check(res, {
      'email send status is 202': (r) => r.status === 202,
      'email send has message_id': (r) => {
        try { return JSON.parse(r.body).message_id !== undefined; }
        catch { return false; }
      },
      'email send duration < 500ms': (r) => r.timings.duration < 500,
    });
  });

  // ── Think time: simulate real user behavior ──
  sleep(Math.random() * 0.5 + 0.1); // 100–600ms between requests
}

// ── Teardown ─────────────────────────────────────────────────────────────────
export function teardown() {
  console.log(`Email send load test complete. Total requests: ${totalRequests.name}`);
}
