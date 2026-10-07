// =============================================================================
// ApexMail — Smoke Test
// =============================================================================
// LT-C-02: Minimal k6 smoke test that verifies the API server is running and
// honouring its documented contract. The first test to run before investing
// resources in full-scale load tests.
//
// Characteristics:
//   - 1 Virtual User (VU), 1 iteration
//   - No ramp-up, immediate execution (< 30s)
//
// Contract asserted (services/mail-server/crates/api-server):
//   - GET /health/live and GET /health/ready return 200
//   - GET /v1/messages with `X-API-Key` returns 200 (authenticated read;
//     the API key header is X-API-Key, NOT Authorization: Bearer)
//   - POST /v1/messages with the real SendMessageRequest shape
//     {from, to[], subject, html?, text?, tags?: string[]} returns 202 and
//     {"data":{"id","status","created_at"},"error":null}
//
// Thresholds (LT-2): the previous only gate was `http_req_failed: rate<1`,
// which a server answering 9 of every 10 requests with an error passed. The
// smoke test now fails at meaningful error rates and every `check()` gates
// through the built-in `checks` rate.
//
// Run (manual/on-demand — the load-gate workflow is archived, ci/README.md §2):
//   K6_API_KEY=am_live_… K6_API_BASE=http://localhost:8080 \
//     K6_FROM_EMAIL=sender@verified.example \
//     k6 run load-tests/http/smoke-test.js
// =============================================================================

import { check } from 'k6';
import http from 'k6/http';
import { API_KEY, BASE_URL, FROM_EMAIL, apiKeyHeaders, testTags } from './test-options.js';

// ── Test Options ────────────────────────────────────────────────────────────

export const options = {
  vus: 1,
  iterations: 1,
  stages: [],

  thresholds: {
    http_req_duration: ['p(95)<2000'],
    // LT-2: rate<0.01 — a real error budget, not "allow 100% failure".
    http_req_failed: ['rate<0.01'],
    // Every documented-contract check must pass.
    checks: ['rate>0.99'],
  },

  discardResponseBodies: false,
  tags: testTags('smoke-test'),
};

// ── Setup ───────────────────────────────────────────────────────────────────

export function setup() {
  if (!API_KEY) {
    throw new Error(
      'K6_API_KEY is required (X-API-Key: am_… for the target tenant); ' +
        'the smoke test asserts the authenticated read and send contract'
    );
  }
  return { start_time: Date.now() };
}

// ── Test Scenario ───────────────────────────────────────────────────────────

export default function () {
  const tags = { test_name: 'smoke-test' };

  // 1. Liveness — no authentication.
  const livenessResp = http.get(`${BASE_URL}/health/live`, {
    headers: { Accept: 'application/json' },
    tags: { ...tags, endpoint: 'liveness' },
  });
  check(livenessResp, {
    'liveness status is 200': (r) => r.status === 200,
    'liveness body is non-empty': (r) => r.body !== undefined && r.body.length > 0,
  });

  // 2. Readiness — DB connectivity etc.
  const readinessResp = http.get(`${BASE_URL}/health/ready`, {
    headers: { Accept: 'application/json' },
    tags: { ...tags, endpoint: 'readiness' },
  });
  check(readinessResp, {
    'readiness status is 200': (r) => r.status === 200,
  });

  // 3. Authenticated read — proves X-API-Key reaches the API key middleware.
  const listResp = http.get(`${BASE_URL}/v1/messages?limit=1`, {
    headers: apiKeyHeaders(),
    tags: { ...tags, endpoint: 'messages-list' },
  });
  check(listResp, {
    'authenticated messages list status is 200': (r) => r.status === 200,
  });

  // 4. Email send — the real SendMessageRequest payload and 202 envelope.
  const emailPayload = JSON.stringify({
    from: FROM_EMAIL,
    to: ['smoke-recipient@example.com'],
    subject: '[Smoke Test] Basic functionality check',
    text: 'This is a smoke test email sent by k6.',
    tags: ['smoke-test'],
  });
  const emailResp = http.post(`${BASE_URL}/v1/messages`, emailPayload, {
    headers: apiKeyHeaders(),
    tags: { ...tags, endpoint: 'email-send' },
  });
  check(emailResp, {
    'email send status is 202': (r) => r.status === 202,
    'email send returns the queued message envelope': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.data !== undefined && body.data.id !== undefined && body.data.status !== undefined;
      } catch {
        return false;
      }
    },
  });

  console.log(`Smoke test completed:
    Liveness:  ${livenessResp.status}
    Readiness: ${readinessResp.status}
    List:      ${listResp.status}
    Email:     ${emailResp.status}
  `);
}
