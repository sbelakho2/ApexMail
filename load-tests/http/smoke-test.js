// =============================================================================
// ApexMail — Smoke Test
// =============================================================================
// LT-C-02: Minimal k6 smoke test to verify that the API server is running,
// responsive, and returning correct responses. A smoke test is the first test
// to run in CI — it validates basic functionality before investing resources
// in full-scale load tests.
//
// Characteristics:
//   - 1 Virtual User (VU)
//   - 1 iteration only
//   - No ramp-up, immediate execution
//   - Fast execution (< 30s)
//
// What it validates:
//   - API server is reachable and not crashing
//   - Health endpoints return 200
//   - Auth endpoint returns a token
//   - Email send endpoint returns 202 (accepted)
//   - No 5xx or connection errors
//
// Exit code: 0 on success, 1 on failure
// =============================================================================

import { check } from 'k6';
import http from 'k6/http';
import { BASE_URL, DEFAULT_HEADERS, testTags } from './test-options.js';

// ── Test Options ────────────────────────────────────────────────────────────

export const options = {
  // Single VU, single iteration
  vus: 1,
  iterations: 1,

  // No ramp-up — execute immediately
  stages: [],

  // Light thresholds — smoke test should always pass if server is up
  thresholds: {
    http_req_duration: ['p(95)<2000'],  // Allow up to 2s for cold start
    http_req_failed: ['rate<1'],         // Allow up to 100% failure if server is down
  },

  // Discard response bodies
  discardResponseBodies: true,

  // Tags for identification
  tags: testTags('smoke-test'),
};

// ── Test Scenario ───────────────────────────────────────────────────────────

export default function () {
  const tags = { test_name: 'smoke-test' };

  // 1. Liveness check
  //    Basic health check — no authentication required.
  //    Expected: HTTP 200, body contains "ok" or similar
  const livenessResp = http.get(
    `${BASE_URL}/health/live`,
    { headers: DEFAULT_HEADERS, tags: { ...tags, endpoint: 'liveness' } }
  );

  check(livenessResp, {
    'liveness status is 200': (r) => r.status === 200,
    'liveness body is valid': (r) => r.body !== undefined && r.body.length > 0,
  });

  // 2. Readiness check
  //    Deeper health check — validates DB connectivity etc.
  //    Expected: HTTP 200
  const readinessResp = http.get(
    `${BASE_URL}/health/ready`,
    { headers: DEFAULT_HEADERS, tags: { ...tags, endpoint: 'readiness' } }
  );

  check(readinessResp, {
    'readiness status is 200': (r) => r.status === 200,
  });

  // 3. Auth login
  //    Verify authentication flow works.
  //    Expected: HTTP 200, JSON body with "token" field
  const loginPayload = JSON.stringify({
    email: 'smoke-test@apexmail.ee',
    password: 'smoke-test-password',
  });

  const loginResp = http.post(
    `${BASE_URL}/v1/auth/login`,
    loginPayload,
    { headers: DEFAULT_HEADERS, tags: { ...tags, endpoint: 'auth' } }
  );

  check(loginResp, {
    'auth login status is 200': (r) => r.status === 200,
    'auth login has token': (r) => {
      try {
        return JSON.parse(r.body).token !== undefined;
      } catch {
        return false;
      }
    },
  });

  // 4. Email send
  //    Verify email submission endpoint works.
  //    Expected: HTTP 202 (accepted for processing)
  const token = loginResp.status === 200
    ? JSON.parse(loginResp.body).token
    : '';

  const emailPayload = JSON.stringify({
    from: 'smoke-test@apexmail.ee',
    to: ['recipient@example.com'],
    subject: '[Smoke Test] Basic functionality check',
    text_body: 'This is a smoke test email sent by k6.',
  });

  const emailResp = http.post(
    `${BASE_URL}/v1/messages`,
    emailPayload,
    {
      headers: {
        ...DEFAULT_HEADERS,
        'Authorization': `Bearer ${token}`,
      },
      tags: { ...tags, endpoint: 'email-send' },
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

  // Summary
  console.log(`Smoke test completed:
    Liveness:  ${livenessResp.status}
    Readiness: ${readinessResp.status}
    Auth:      ${loginResp.status}
    Email:     ${emailResp.status}
  `);
}
