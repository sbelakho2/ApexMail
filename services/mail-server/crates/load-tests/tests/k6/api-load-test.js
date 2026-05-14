// ApexMail API Load Test — k6 script
// Targets all major API endpoints with realistic traffic patterns.
// Ramp-up stages: 10 → 50 → 100 → 200 VUs
// Thresholds: p95 < 500ms, error rate < 1%
//
// Usage:
//   k6 run api-load-test.js
//   K6_API_BASE=http://staging.apexmail.ee K6_API_KEY=xxx k6 run api-load-test.js

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// ── Custom metrics ───────────────────────────────────────────────────────────
const emailSendDuration = new Trend('email_send_duration');
const emailListDuration = new Trend('email_list_duration');
const analyticsDuration = new Trend('analytics_duration');
const templateDuration = new Trend('template_duration');
const domainDuration = new Trend('domain_duration');
const errorRate = new Rate('error_rate');
const totalRequests = new Counter('total_requests');

// ── Configuration ────────────────────────────────────────────────────────────
const API_BASE = __ENV.K6_API_BASE || 'http://localhost:3000';
const API_KEY = __ENV.K6_API_KEY || 'test-api-key-00000000000000000000000000000';

const HEADERS = {
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
    { duration: '2m', target: 200 },  // Ramp-up to 200 VUs
    { duration: '5m', target: 200 },  // Stay at 200 VUs
    { duration: '2m', target: 0 },    // Ramp-down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1000'],
    http_req_failed: ['rate<0.01'],
    email_send_duration: ['p(95)<1000'],
    error_rate: ['rate<0.01'],
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
    subject: `Load Test Email — VU ${__VU} — ${Date.now()}`,
    text_body: `This is a load test email body. VU=${__VU}, time=${Date.now()}`,
    html_body: `<html><body><p>Load test email</p><p>VU=${__VU}</p></body></html>`,
    tags: { load_test: 'true', vu: String(__VU) },
  });
}

function templatePayload() {
  return JSON.stringify({
    name: `load-test-template-${__VU}-${Date.now()}`,
    subject: `Hello {{name}} — VU ${__VU}`,
    content: `<html><body><p>Hello {{name}}, this is a load test.</p></body></html>`,
  });
}

// ── Main test function ───────────────────────────────────────────────────────
export default function () {
  // ── Weight distribution: realistic traffic mix ──
  // 40% send email, 20% list emails, 15% analytics, 15% templates, 10% domains
  const roll = Math.random();

  if (roll < 0.40) {
    // ── SEND EMAIL ─────────────────────────────────────────────────────────
    group('Send Email', function () {
      const url = `${API_BASE}/v1/email/send`;
      const payload = emailPayload();
      const res = http.post(url, payload, { headers: HEADERS });
      emailSendDuration.add(res.timings.duration);
      totalRequests.add(1);
      errorRate.add(res.status >= 400);

      check(res, {
        'send email status is 202': (r) => r.status === 202,
        'send email has message_id': (r) => {
          try { return JSON.parse(r.body).message_id !== undefined; }
          catch { return false; }
        },
        'send email duration < 2s': (r) => r.timings.duration < 2000,
      });
    });

  } else if (roll < 0.60) {
    // ── LIST EMAILS ────────────────────────────────────────────────────────
    group('List Emails', function () {
      const url = `${API_BASE}/v1/email?limit=50&page=1`;
      const res = http.get(url, { headers: HEADERS });
      emailListDuration.add(res.timings.duration);
      totalRequests.add(1);
      errorRate.add(res.status >= 400);

      check(res, {
        'list emails status is 200': (r) => r.status === 200,
        'list emails duration < 500ms': (r) => r.timings.duration < 500,
      });
    });

  } else if (roll < 0.75) {
    // ── ANALYTICS ──────────────────────────────────────────────────────────
    group('Analytics', function () {
      const url = `${API_BASE}/v1/analytics/summary?period=24h`;
      const res = http.get(url, { headers: HEADERS });
      analyticsDuration.add(res.timings.duration);
      totalRequests.add(1);
      errorRate.add(res.status >= 400);

      check(res, {
        'analytics status is 200': (r) => r.status === 200,
        'analytics duration < 500ms': (r) => r.timings.duration < 500,
      });
    });

  } else if (roll < 0.90) {
    // ── TEMPLATES ─────────────────────────────────────────────────────────
    group('Templates', function () {
      // Create a template
      const createUrl = `${API_BASE}/v1/templates`;
      const payload = templatePayload();
      const createRes = http.post(createUrl, payload, { headers: HEADERS });
      templateDuration.add(createRes.timings.duration);
      totalRequests.add(1);

      if (createRes.status === 201) {
        let templateId = null;
        try { templateId = JSON.parse(createRes.body).id; } catch { /* ignore */ }

        if (templateId) {
          // List templates
          const listRes = http.get(`${API_BASE}/v1/templates`, { headers: HEADERS });
          templateDuration.add(listRes.timings.duration);
          totalRequests.add(1);

          // Get template by ID
          const getRes = http.get(`${API_BASE}/v1/templates/${templateId}`, { headers: HEADERS });
          templateDuration.add(getRes.timings.duration);
          totalRequests.add(1);

          // Delete template
          const delRes = http.del(`${API_BASE}/v1/templates/${templateId}`, null, { headers: HEADERS });
          templateDuration.add(delRes.timings.duration);
          totalRequests.add(1);
        }
      }

      errorRate.add(createRes.status >= 400);
      check(createRes, {
        'template create status is 201': (r) => r.status === 201,
      });
    });

  } else {
    // ── DOMAINS ────────────────────────────────────────────────────────────
    group('Domains', function () {
      const url = `${API_BASE}/v1/domains`;
      const res = http.get(url, { headers: HEADERS });
      domainDuration.add(res.timings.duration);
      totalRequests.add(1);
      errorRate.add(res.status >= 400);

      check(res, {
        'domains status is 200': (r) => r.status === 200,
        'domains duration < 500ms': (r) => r.timings.duration < 500,
      });
    });
  }

  // ── Think time: simulate real user behavior ──
  sleep(Math.random() * 0.5 + 0.1); // 100–600ms between requests
}

// ── Teardown ─────────────────────────────────────────────────────────────────
export function teardown() {
  console.log(`API load test complete. Total requests: ${totalRequests.name}`);
}
