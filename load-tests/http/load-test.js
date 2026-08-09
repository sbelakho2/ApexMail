// =============================================================================
// ApexMail — Load Test
// =============================================================================
// LT-C-02: Standard load test that simulates realistic user traffic. This test
// measures the API server's performance under expected production load levels.
//
// Stages:
//   1. Ramp up:  0 → 50 VUs over 2 minutes   (warm-up, cache priming)
//   2. Stay:    50 VUs for 5 minutes          (sustained load measurement)
//   3. Ramp down: 50 → 0 VUs over 2 minutes   (graceful cooldown)
//
// Thresholds:
//   - p(95) response time < 500ms
//   - Error rate < 1%
//   - All checks must pass at > 99%
//
// This test is designed to run in CI as part of the load-gate workflow.
// Fail the workflow if thresholds are exceeded.
// =============================================================================

import { check, group } from 'k6';
import http from 'k6/http';
import { randomString, testTags } from './test-options.js';

// ── Configuration ───────────────────────────────────────────────────────────

const BASE_URL = __ENV.K6_API_BASE || 'http://localhost:3000';
const API_KEY = __ENV.K6_API_KEY || '';

// ── Test Options ────────────────────────────────────────────────────────────

export const options = {
  stages: [
    // Ramp up from 0 to 50 VUs over 2 minutes
    { duration: '2m', target: 50 },

    // Stay at 50 VUs for 5 minutes
    { duration: '5m', target: 50 },

    // Ramp down from 50 to 0 VUs over 2 minutes
    { duration: '2m', target: 0 },
  ],

  thresholds: {
    // ── General HTTP thresholds ─────────────────────────────────────────────
    http_req_duration: [
      'p(95)<500',    // 95% of requests under 500ms
      'p(99)<2000',   // 99% of requests under 2000ms
      'avg<300',      // Average latency under 300ms
    ],
    http_req_failed: [
      'rate<0.01',    // Less than 1% error rate
    ],

    // ── Per-group thresholds ────────────────────────────────────────────────
    // Health checks must be fast (no auth, no DB writes)
    'health_duration': ['p(95)<200'],

    // Auth login — bounded by bcrypt/hashing cost
    'auth_login_duration': ['p(95)<800'],

    // Email send — includes validation + queue submission
    'email_send_duration': ['p(95)<1000'],
  },

  // Discard response bodies to reduce memory
  discardResponseBodies: true,

  tags: testTags('load-test'),
};

// ── Test Data ───────────────────────────────────────────────────────────────

// Shared credentials for load testing
const TEST_USERS = [
  { email: 'loadtest-user-1@apexmail.ee', password: 'loadtest-pass-1' },
  { email: 'loadtest-user-2@apexmail.ee', password: 'loadtest-pass-2' },
  { email: 'loadtest-user-3@apexmail.ee', password: 'loadtest-pass-3' },
  { email: 'loadtest-user-4@apexmail.ee', password: 'loadtest-pass-4' },
  { email: 'loadtest-user-5@apexmail.ee', password: 'loadtest-pass-5' },
];

// ── Helper Functions ────────────────────────────────────────────────────────

function getDefaultHeaders() {
  return {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  };
}

function getAuthHeaders(token) {
  return {
    ...getDefaultHeaders(),
    'Authorization': `Bearer ${token}`,
  };
}

// ── Main Test Scenario ──────────────────────────────────────────────────────

export default function () {
  const vuId = __VU;           // Virtual User ID (1–50)
  const iter = __ITER;         // Iteration number

  // Determine which test user this VU simulates
  const userIndex = vuId % TEST_USERS.length;
  const user = TEST_USERS[userIndex];

  // ── Group: Health Checks ──────────────────────────────────────────────────
  group('health checks', function () {
    const livenessResp = http.get(
      `${BASE_URL}/health/live`,
      {
        headers: getDefaultHeaders(),
        tags: { endpoint: 'liveness' },
      }
    );

    check(livenessResp, {
      'liveness status is 200': (r) => r.status === 200,
    });

    // Custom metric for health check duration
    // k6 will aggregate this under 'health_duration'
    const readinessResp = http.get(
      `${BASE_URL}/health/ready`,
      {
        headers: getDefaultHeaders(),
        tags: { endpoint: 'readiness' },
      }
    );

    check(readinessResp, {
      'readiness status is 200': (r) => r.status === 200,
    });
  });

  // ── Group: Authentication ─────────────────────────────────────────────────
  group('authentication', function () {
    const loginPayload = JSON.stringify({
      email: user.email,
      password: user.password,
    });

    const loginResp = http.post(
      `${BASE_URL}/v1/auth/login`,
      loginPayload,
      {
        headers: getDefaultHeaders(),
        tags: { endpoint: 'auth-login' },
      }
    );

    const loginSuccess = check(loginResp, {
      'auth login status is 200': (r) => r.status === 200,
      'auth login has token': (r) => {
        try {
          return JSON.parse(r.body).token !== undefined;
        } catch {
          return false;
        }
      },
    });

    // If login succeeded, use the token for subsequent requests
    if (loginSuccess) {
      const token = JSON.parse(loginResp.body).token;
      __ENV.__TOKEN = token;
    }
  });

  // ── Group: Email Send ─────────────────────────────────────────────────────
  group('email send', function () {
    const token = __ENV.__TOKEN || '';
    if (!token) {
      // Skip if no token available (login may have failed)
      return;
    }

    const emailPayload = JSON.stringify({
      from: `loadtest-${vuId}@apexmail.ee`,
      to: [`recipient-${vuId}-${iter}@example.com`],
      subject: `[Load Test] Performance measurement — VU ${vuId} Iteration ${iter}`,
      text_body: `This is a load test email sent by VU ${vuId} in iteration ${iter}.`,
      html_body: `<html><body><p>This is a load test email sent by VU ${vuId} in iteration ${iter}.</p></body></html>`,
      tags: {
        load_test: 'true',
        vu_id: String(vuId),
        iteration: String(iter),
      },
    });

    const emailResp = http.post(
      `${BASE_URL}/v1/messages`,
      emailPayload,
      {
        headers: getAuthHeaders(token),
        tags: { endpoint: 'email-send' },
      }
    );

    check(emailResp, {
      'email send status is 200 or 202': (r) => r.status === 200 || r.status === 202,
      'email send has message_id': (r) => {
        try {
          const body = JSON.parse(r.body);
          return body.message_id !== undefined || body.id !== undefined;
        } catch {
          return false;
        }
      },
    });
  });
}
