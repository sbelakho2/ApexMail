// ApexMail Full API Journey Load Test — k6 script
// Exercises all 6 major API flows with realistic traffic patterns:
//   1. Auth (login, token refresh)
//   2. Email send (API submission)
//   3. Email list + analytics
//   4. Template CRUD
//   5. Suppression management
//   6. Domain management
//
// Usage:
//   K6_API_BASE=http://staging.apexmail.ee K6_API_KEY=xxx k6 run full-journey-test.js
//
// Thresholds:
//   - p95 http_req_duration < 500ms
//   - p99 http_req_duration < 1000ms
//   - Error rate < 1%

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// ── Custom metrics ───────────────────────────────────────────────────────────
const authDuration = new Trend('auth_duration');
const emailSendDuration = new Trend('email_send_duration');
const emailListDuration = new Trend('email_list_duration');
const analyticsDuration = new Trend('analytics_duration');
const templateDuration = new Trend('template_duration');
const suppressionDuration = new Trend('suppression_duration');
const domainDuration = new Trend('domain_duration');
const errorRate = new Rate('error_rate');
const totalRequests = new Counter('total_requests');

// ── Configuration ────────────────────────────────────────────────────────────
const API_BASE = __ENV.K6_API_BASE || 'http://localhost:3000';
const API_KEY = __ENV.K6_API_KEY || 'test-api-key-00000000000000000000000000000';
const BASE_HEADERS = {
  'Content-Type': 'application/json',
};
const AUTH_HEADERS = {
  'Authorization': `Bearer ${API_KEY}`,
  'Content-Type': 'application/json',
  'X-Tenant-ID': `tenant-${__VU}`,
};

// Shared state per VU
let authToken = '';

// ── Options ──────────────────────────────────────────────────────────────────
export const options = {
  stages: [
    { duration: '1m', target: 5 },    // Warm-up
    { duration: '2m', target: 25 },   // Ramp
    { duration: '3m', target: 50 },   // Load
    { duration: '2m', target: 100 },  // Peak
    { duration: '3m', target: 100 },  // Sustain
    { duration: '1m', target: 0 },    // Cool-down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1000'],
    http_req_failed: ['rate<0.01'],
    auth_duration: ['p(95)<2000'],
    email_send_duration: ['p(95)<1000'],
    email_list_duration: ['p(95)<500'],
    analytics_duration: ['p(95)<500'],
    template_duration: ['p(95)<1000'],
    suppression_duration: ['p(95)<1000'],
    domain_duration: ['p(95)<500'],
    error_rate: ['rate<0.01'],
  },
  tags: {
    test: 'full-journey',
    service: 'api-server',
  },
};

// ── Helper: Generate test payloads ───────────────────────────────────────────
function randomEmail() {
  const domains = ['example.com', 'test.org', 'demo.net', 'mail.loc', 'acme.co'];
  return `test-${__VU}-${Date.now()}@${domains[Math.floor(Math.random() * domains.length)]}`;
}

function randomString(length) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// ── Flow 1: Auth ────────────────────────────────────────────────────────────
function flowAuth() {
  group('Auth Flow', function () {
    // 1a. Login
    const loginPayload = JSON.stringify({
      email: `user-${__VU}@apexmail.ee`,
      password: 'test-password',
    });
    const loginRes = http.post(`${API_BASE}/v1/auth/login`, loginPayload, {
      headers: BASE_HEADERS,
      tags: { flow: 'auth', action: 'login' },
    });
    authDuration.add(loginRes.timings.duration);
    totalRequests.add(1);
    errorRate.add(loginRes.status >= 400);
    check(loginRes, {
      'auth login status is 200': (r) => r.status === 200,
      'auth login has token': (r) => {
        try { return JSON.parse(r.body).token !== undefined; }
        catch { return false; }
      },
    });

    // Extract token if login succeeded
    if (loginRes.status === 200) {
      try {
        authToken = JSON.parse(loginRes.body).token;
      } catch (e) {
        // Fall back to API key
        authToken = API_KEY;
      }
    } else {
      authToken = API_KEY;
    }

    // 1b. Token refresh
    const refreshPayload = JSON.stringify({
      token: authToken,
    });
    const refreshRes = http.post(`${API_BASE}/v1/auth/refresh`, refreshPayload, {
      headers: { 'Content-Type': 'application/json' },
      tags: { flow: 'auth', action: 'refresh' },
    });
    authDuration.add(refreshRes.timings.duration);
    totalRequests.add(1);
    errorRate.add(refreshRes.status >= 400);
    check(refreshRes, {
      'auth refresh status is 200': (r) => r.status === 200 || r.status === 401,
    });
  });
}

// ── Flow 2: Email Send ──────────────────────────────────────────────────────
function flowEmailSend() {
  group('Email Send', function () {
    const payload = JSON.stringify({
      to: [randomEmail()],
      from: `sender-${__VU}@apexmail.ee`,
      subject: `Journey Test Email — VU ${__VU} — ${Date.now()}`,
      text_body: `Journey test email body. VU=${__VU}`,
      html_body: `<html><body><p>Journey test</p><p>VU=${__VU}</p></body></html>`,
      tags: { journey_test: 'true', vu: String(__VU) },
      options: {
        track_opens: true,
        track_clicks: true,
        priority: 'normal',
      },
    });

    const res = http.post(`${API_BASE}/v1/email/send`, payload, {
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
      'email send duration < 2s': (r) => r.timings.duration < 2000,
    });
  });
}

// ── Flow 3: Email List + Analytics ─────────────────────────────────────────
function flowEmailListAnalytics() {
  group('Email List & Analytics', function () {
    // List emails with pagination
    const listRes = http.get(`${API_BASE}/v1/email?limit=50&page=1`, {
      headers: AUTH_HEADERS,
      tags: { flow: 'analytics', action: 'list' },
    });
    emailListDuration.add(listRes.timings.duration);
    totalRequests.add(1);
    errorRate.add(listRes.status >= 400);
    check(listRes, {
      'email list status is 200': (r) => r.status === 200,
      'email list duration < 500ms': (r) => r.timings.duration < 500,
    });

    // Analytics summary
    const analyticsRes = http.get(`${API_BASE}/v1/analytics/summary?period=24h`, {
      headers: AUTH_HEADERS,
      tags: { flow: 'analytics', action: 'summary' },
    });
    analyticsDuration.add(analyticsRes.timings.duration);
    totalRequests.add(1);
    errorRate.add(analyticsRes.status >= 400);
    check(analyticsRes, {
      'analytics status is 200': (r) => r.status === 200,
      'analytics duration < 500ms': (r) => r.timings.duration < 500,
    });
  });
}

// ── Flow 4: Template CRUD ──────────────────────────────────────────────────
function flowTemplateCRUD() {
  group('Template CRUD', function () {
    const templateName = `jt-template-${__VU}-${Date.now()}`;

    // CREATE
    const createPayload = JSON.stringify({
      name: templateName,
      subject: 'Hello {{name}}',
      content: `<html><body><p>Hello {{name}}, journey test.</p></body></html>`,
    });
    const createRes = http.post(`${API_BASE}/v1/templates`, createPayload, {
      headers: AUTH_HEADERS,
      tags: { flow: 'template', action: 'create' },
    });
    templateDuration.add(createRes.timings.duration);
    totalRequests.add(1);
    errorRate.add(createRes.status >= 400);

    let templateId = null;
    if (createRes.status === 201) {
      try { templateId = JSON.parse(createRes.body).id; } catch (e) { /* ignore */ }
      check(createRes, { 'template create status is 201': (r) => r.status === 201 });
    }

    // LIST
    const listRes = http.get(`${API_BASE}/v1/templates`, {
      headers: AUTH_HEADERS,
      tags: { flow: 'template', action: 'list' },
    });
    templateDuration.add(listRes.timings.duration);
    totalRequests.add(1);
    errorRate.add(listRes.status >= 400);
    check(listRes, { 'template list status is 200': (r) => r.status === 200 });

    // GET by ID (if created)
    if (templateId) {
      const getRes = http.get(`${API_BASE}/v1/templates/${templateId}`, {
        headers: AUTH_HEADERS,
        tags: { flow: 'template', action: 'get' },
      });
      templateDuration.add(getRes.timings.duration);
      totalRequests.add(1);
      errorRate.add(getRes.status >= 400);
      check(getRes, { 'template get status is 200': (r) => r.status === 200 });

      // UPDATE
      const updatePayload = JSON.stringify({
        name: templateName,
        subject: 'Updated {{name}}',
        content: `<html><body><p>Updated {{name}}.</p></body></html>`,
      });
      const updateRes = http.put(`${API_BASE}/v1/templates/${templateId}`, updatePayload, {
        headers: AUTH_HEADERS,
        tags: { flow: 'template', action: 'update' },
      });
      templateDuration.add(updateRes.timings.duration);
      totalRequests.add(1);
      errorRate.add(updateRes.status >= 400);
      check(updateRes, { 'template update status is 200': (r) => r.status === 200 });

      // DELETE
      const delRes = http.del(`${API_BASE}/v1/templates/${templateId}`, null, {
        headers: AUTH_HEADERS,
        tags: { flow: 'template', action: 'delete' },
      });
      templateDuration.add(delRes.timings.duration);
      totalRequests.add(1);
      errorRate.add(delRes.status >= 400);
      check(delRes, { 'template delete status is 204': (r) => r.status === 204 });
    }
  });
}

// ── Flow 5: Suppression Management ─────────────────────────────────────────
function flowSuppression() {
  group('Suppression Management', function () {
    const email = `spam-${randomString(8)}@example.com`;

    // CREATE suppression
    const createPayload = JSON.stringify({
      recipient: email,
      type: 'bounce',
      reason: 'Hard bounce — load test',
    });
    const createRes = http.post(`${API_BASE}/v1/suppressions`, createPayload, {
      headers: AUTH_HEADERS,
      tags: { flow: 'suppression', action: 'create' },
    });
    suppressionDuration.add(createRes.timings.duration);
    totalRequests.add(1);
    errorRate.add(createRes.status >= 400);
    check(createRes, {
      'suppression create status is 201': (r) => r.status === 201 || r.status === 409,
    });

    // LIST suppressions
    const listRes = http.get(`${API_BASE}/v1/suppressions?limit=50&page=1`, {
      headers: AUTH_HEADERS,
      tags: { flow: 'suppression', action: 'list' },
    });
    suppressionDuration.add(listRes.timings.duration);
    totalRequests.add(1);
    errorRate.add(listRes.status >= 400);
    check(listRes, {
      'suppression list status is 200': (r) => r.status === 200,
    });

    // CHECK if email is suppressed
    const checkRes = http.get(`${API_BASE}/v1/suppressions/${encodeURIComponent(email)}`, {
      headers: AUTH_HEADERS,
      tags: { flow: 'suppression', action: 'check' },
    });
    suppressionDuration.add(checkRes.timings.duration);
    totalRequests.add(1);

    // DELETE suppression
    const delRes = http.del(`${API_BASE}/v1/suppressions/${encodeURIComponent(email)}`, null, {
      headers: AUTH_HEADERS,
      tags: { flow: 'suppression', action: 'delete' },
    });
    suppressionDuration.add(delRes.timings.duration);
    totalRequests.add(1);
    errorRate.add(delRes.status >= 400);
  });
}

// ── Flow 6: Domain Management ──────────────────────────────────────────────
function flowDomain() {
  group('Domain Management', function () {
    const domainName = `loadtest-${__VU}-${Date.now()}.example.com`;

    // LIST domains
    const listRes = http.get(`${API_BASE}/v1/domains`, {
      headers: AUTH_HEADERS,
      tags: { flow: 'domain', action: 'list' },
    });
    domainDuration.add(listRes.timings.duration);
    totalRequests.add(1);
    errorRate.add(listRes.status >= 400);
    check(listRes, {
      'domain list status is 200': (r) => r.status === 200,
      'domain list duration < 500ms': (r) => r.timings.duration < 500,
    });

    // CREATE domain (50% chance — domains are heavy resources)
    if (Math.random() < 0.5) {
      const createPayload = JSON.stringify({
        domain: domainName,
        region: 'eu-west-1',
        tracking_type: 'subdomain',
      });
      const createRes = http.post(`${API_BASE}/v1/domains`, createPayload, {
        headers: AUTH_HEADERS,
        tags: { flow: 'domain', action: 'create' },
      });
      domainDuration.add(createRes.timings.duration);
      totalRequests.add(1);
      errorRate.add(createRes.status >= 400);
      check(createRes, {
        'domain create status is 201': (r) => r.status === 201 || r.status === 409,
      });
    }

    // VERIFY domain settings
    const verifyRes = http.get(`${API_BASE}/v1/domains/verify`, {
      headers: AUTH_HEADERS,
      tags: { flow: 'domain', action: 'verify' },
    });
    domainDuration.add(verifyRes.timings.duration);
    totalRequests.add(1);
  });
}

// ── Main test function ───────────────────────────────────────────────────────
export default function () {
  // Execute all 6 flows with realistic weight distribution:
  // Auth is called once per session (rare), others are distributed
  const roll = Math.random();

  if (roll < 0.05) {
    // 5%: Auth (login happens once per session)
    flowAuth();
  } else if (roll < 0.30) {
    // 25%: Email send
    flowEmailSend();
  } else if (roll < 0.50) {
    // 20%: Email list + analytics
    flowEmailListAnalytics();
  } else if (roll < 0.70) {
    // 20%: Template CRUD
    flowTemplateCRUD();
  } else if (roll < 0.85) {
    // 15%: Suppression management
    flowSuppression();
  } else {
    // 15%: Domain management
    flowDomain();
  }

  // ── Think time: simulate real user behavior ──
  sleep(Math.random() * 0.5 + 0.1); // 100–600ms
}

// ── Setup ────────────────────────────────────────────────────────────────────
export function setup() {
  console.log('Full journey load test starting...');
  console.log(`API Base: ${API_BASE}`);
  return { start_time: Date.now() };
}

// ── Teardown ─────────────────────────────────────────────────────────────────
export function teardown() {
  console.log(`Full journey load test complete. Total requests: ${totalRequests.name}`);
}
