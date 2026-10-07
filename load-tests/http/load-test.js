// =============================================================================
// ApexMail — Load Test
// =============================================================================
// LT-C-01: Standard load test that simulates realistic API traffic against a
// running api-server.
//
// Real API contract (services/mail-server/crates/api-server):
//   * Auth: authenticated calls send `X-API-Key: am_…` (middleware/auth.rs).
//     `POST /v1/auth/login` is a CSRF-gated session flow that returns
//     `{expires_at, user}` (no JSON token), so it is deliberately NOT driven
//     here — see http-journey/auth-load-test.js for that interactive flow.
//   * Send: `POST /v1/messages` accepts
//     {from, to[], subject, html?, text?, tags?: string[]}
//     (SendMessageRequest, deny_unknown_fields) and answers 202 with
//     {"data":{"id","status","created_at"},"error":null}.
//   * Health: GET /health/live and GET /health/ready.
//
// Stages:
//   1. Ramp up:  0 → 50 VUs over 2 minutes   (warm-up)
//   2. Stay:    50 VUs for 5 minutes          (sustained load measurement)
//   3. Ramp down: 50 → 0 VUs over 2 minutes   (cooldown)
//
// Thresholds: p95 < 500ms, p99 < 2000ms, error rate < 1%, per-endpoint
// trends (LT-1: the trends are now actually DEFINED — the previous thresholds
// referenced metrics that did not exist, so k6 refused to start at all).
//
// Run (manual/on-demand — the load-gate workflow is archived, ci/README.md §2):
//   K6_API_KEY=am_live_… K6_API_BASE=http://localhost:8080 \
//     K6_FROM_EMAIL=sender@verified.example \
//     k6 run load-tests/http/load-test.js
// =============================================================================

import { check, group, sleep } from 'k6';
import http from 'k6/http';
import { Trend, Counter } from 'k6/metrics';
import { API_KEY, BASE_URL, FROM_EMAIL, apiKeyHeaders, testTags } from './test-options.js';

// ── Custom metrics ──────────────────────────────────────────────────────────

const healthDuration = new Trend('health_duration');
const authProbeDuration = new Trend('auth_probe_duration');
const emailSendDuration = new Trend('email_send_duration');
const emailSendAccepted = new Counter('email_send_accepted');

// ── Test Options ────────────────────────────────────────────────────────────

export const options = {
  stages: [
    { duration: '2m', target: 50 },   // Ramp up to 50 VUs
    { duration: '5m', target: 50 },   // Sustain at 50 VUs
    { duration: '2m', target: 0 },    // Ramp down
  ],

  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<2000', 'avg<300'],
    http_req_failed: ['rate<0.01'],
    health_duration: ['p(95)<200'],
    auth_probe_duration: ['p(95)<800'],
    email_send_duration: ['p(95)<1000'],
    // A run that never accepted a single message is not a passing run
    // (LT-3: the old script silently skipped the whole send scenario).
    email_send_accepted: ['count>0'],
  },

  // Bodies are needed to assert the response envelope.
  discardResponseBodies: false,

  // p(99) must be exported for the baseline-comparison mapping below.
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(50)', 'p(95)', 'p(99)', 'count'],

  tags: testTags('load-test'),
};

// ── Setup ───────────────────────────────────────────────────────────────────

export function setup() {
  // Fail fast and loudly: without a key every authenticated request would be
  // a 401 and the send scenario would measure nothing.
  if (!API_KEY) {
    throw new Error(
      'K6_API_KEY is required (X-API-Key: am_… for the target tenant); ' +
        'refusing to run a load test whose authenticated scenarios cannot succeed'
    );
  }
  console.log(`Load test: base=${BASE_URL} from=${FROM_EMAIL}`);
  return { start_time: Date.now() };
}

// ── Main Test Scenario ──────────────────────────────────────────────────────

export default function () {
  const vuId = __VU;
  const iter = __ITER;

  // ── Group: Health Checks ──────────────────────────────────────────────────
  group('health checks', function () {
    const livenessResp = http.get(`${BASE_URL}/health/live`, {
      tags: { endpoint: 'liveness' },
    });
    healthDuration.add(livenessResp.timings.duration);
    check(livenessResp, {
      'liveness status is 200': (r) => r.status === 200,
    });

    const readinessResp = http.get(`${BASE_URL}/health/ready`, {
      tags: { endpoint: 'readiness' },
    });
    healthDuration.add(readinessResp.timings.duration);
    check(readinessResp, {
      'readiness status is 200': (r) => r.status === 200,
    });
  });

  // ── Group: Authenticated probe (X-API-Key) ────────────────────────────────
  group('authenticated probe', function () {
    const probeResp = http.get(`${BASE_URL}/v1/messages?limit=1`, {
      headers: apiKeyHeaders(),
      tags: { endpoint: 'auth-probe' },
    });
    authProbeDuration.add(probeResp.timings.duration);
    check(probeResp, {
      'authenticated read status is 200': (r) => r.status === 200,
    });
  });

  // ── Group: Email Send ─────────────────────────────────────────────────────
  group('email send', function () {
    // The real SendMessageRequest shape: html/text (not html_body/text_body)
    // and tags as a string list (not an object).
    const emailPayload = JSON.stringify({
      from: FROM_EMAIL,
      to: [`loadtest-${vuId}-${iter}@example.com`],
      subject: `[Load Test] VU ${vuId} iteration ${iter}`,
      text: `Load test message sent by VU ${vuId} in iteration ${iter}.`,
      html: `<p>Load test message sent by VU ${vuId} in iteration ${iter}.</p>`,
      tags: ['load-test'],
    });

    const emailResp = http.post(`${BASE_URL}/v1/messages`, emailPayload, {
      headers: apiKeyHeaders(),
      tags: { endpoint: 'email-send' },
    });
    emailSendDuration.add(emailResp.timings.duration);

    check(emailResp, {
      'email send status is 202': (r) => r.status === 202,
      'email send returns the queued message envelope': (r) => {
        try {
          const body = JSON.parse(r.body);
          return body.data !== undefined && body.data.id !== undefined;
        } catch {
          return false;
        }
      },
    });
    if (emailResp.status === 202) {
      emailSendAccepted.add(1);
    }
  });

  // Think time: a VU loop without it hammers the API at a rate no real
  // client produces (and trips per-IP anti-burst middleware even at low VU
  // counts).
  sleep(Math.random() * 0.8 + 0.4); // 400–1200ms
}
