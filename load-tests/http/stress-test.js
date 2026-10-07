// =============================================================================
// ApexMail — Stress Test
// =============================================================================
// LT-C-02: Stress test that pushes the API server beyond expected capacity to
// find its breaking point.
//
// Stages:
//   1. Ramp to 50 VUs  over 1m     — warm-up
//   2. Spike to 200 VUs over 30s
//   3. Stay at 200 VUs for 3m
//   4. Second surge over 30s
//   5. Stay at 200 VUs for 3m
//   6. Ramp down to 0 VUs over 1m
//
// Real API contract (see load-test.js): X-API-Key authentication, health at
// /health/live|/health/ready, send at POST /v1/messages with
// {from, to[], subject, html?, text?, tags?: string[]} → 202 envelope.
//
// Thresholds:
//   - p(99) < 2000ms  — tail latency must stay bounded
//   - Error rate < 5% — higher tolerance under extreme load
//   - Sustained request rate > 100 req/s
//
// Run (manual/on-demand — the load-gate workflow is archived, ci/README.md §2):
//   K6_API_KEY=am_live_… K6_API_BASE=http://localhost:8080 \
//     K6_FROM_EMAIL=sender@verified.example \
//     k6 run load-tests/http/stress-test.js
// =============================================================================

import { check, group } from 'k6';
import http from 'k6/http';
import { API_KEY, BASE_URL, FROM_EMAIL, apiKeyHeaders, randomString, testTags } from './test-options.js';

// ── Test Options ────────────────────────────────────────────────────────────

export const options = {
  stages: [
    { duration: '1m', target: 50 },
    { duration: '30s', target: 200 },
    { duration: '3m', target: 200 },
    { duration: '30s', target: 200 },
    { duration: '3m', target: 200 },
    { duration: '1m', target: 0 },
  ],

  thresholds: {
    http_req_duration: ['p(95)<1000', 'p(99)<2000', 'avg<800'],
    http_req_failed: ['rate<0.05'],
    http_reqs: ['rate>100'],
  },

  discardResponseBodies: true,
  noConnectionReuse: true,
  tags: testTags('stress-test'),
};

// ── Setup ───────────────────────────────────────────────────────────────────

export function setup() {
  if (!API_KEY) {
    throw new Error(
      'K6_API_KEY is required (X-API-Key: am_… for the target tenant); ' +
        'refusing to run a stress test whose authenticated scenarios cannot succeed'
    );
  }
  return { start_time: Date.now() };
}

// ── Test Scenario ───────────────────────────────────────────────────────────

export default function () {
  const vuId = __VU;
  const iter = __ITER;

  // ── Health Check (lightweight, no auth) ───────────────────────────────────
  group('health check', function () {
    const endpoint = iter % 2 === 0 ? 'live' : 'ready';
    const resp = http.get(`${BASE_URL}/health/${endpoint}`, {
      tags: { endpoint: `health-${endpoint}` },
    });
    check(resp, {
      'health status is 200': (r) => r.status === 200,
    });
  });

  // ── Authenticated probe (X-API-Key) ───────────────────────────────────────
  group('authenticated probe', function () {
    const resp = http.get(`${BASE_URL}/v1/messages?limit=1`, {
      headers: apiKeyHeaders(),
      tags: { endpoint: 'auth-probe' },
    });
    check(resp, {
      'authenticated read status is 200 or 429': (r) => r.status === 200 || r.status === 429,
      'authenticated read not 5xx': (r) => r.status < 500,
    });
  });

  // ── Email Send (heaviest operation) ───────────────────────────────────────
  group('email send', function () {
    const emailPayload = JSON.stringify({
      from: FROM_EMAIL,
      to: [`stress-recipient-${vuId}-${iter}@example.com`],
      subject: `[Stress Test] VU ${vuId} iteration ${iter} — ${randomString(8)}`,
      text: 'This is a stress test email. '.repeat(20),
      tags: ['stress-test'],
    });

    const emailResp = http.post(`${BASE_URL}/v1/messages`, emailPayload, {
      headers: apiKeyHeaders(),
      tags: { endpoint: 'email-send' },
    });

    check(emailResp, {
      'email status is 202 or 429': (r) => r.status === 202 || r.status === 429,
      'email not 5xx': (r) => r.status < 500,
    });
  });
}
