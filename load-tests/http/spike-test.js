// =============================================================================
// ApexMail — Spike Test
// =============================================================================
// LT-C-02: Spike test that simulates sudden, dramatic increases in traffic.
// Unlike the stress test (which maintains high load), the spike test rapidly
// alternates between low and high load to measure:
//
//   1. How quickly the system can scale up (autoscaling response time)
//   2. Whether the system survives instantaneous load spikes
//   3. Recovery behaviour when load drops (does it scale down gracefully?)
//   4. Cold start behaviour of connection pools and caches
//
// Stages:
//   1. Baseline:    10 VUs for 2m         — establish steady state
//   2. Spike 1:     10 → 200 VUs in 10s   — sudden traffic surge
//   3. Recovery 1:  200 → 10 VUs in 10s   — immediate drop
//   4. Baseline 2:  10 VUs for 1m         — recovery period
//   5. Spike 2:     10 → 200 VUs in 10s   — second surge
//   6. Recovery 2:  200 → 10 VUs in 10s   — immediate drop
//   7. Baseline 3:  10 VUs for 1m         — final recovery
//   8. Cooldown:    10 → 0 VUs in 30s
//
// Real API contract (see load-test.js): X-API-Key authentication, health at
// /health/live|/health/ready, send at POST /v1/messages with
// {from, to[], subject, html?, text?, tags?: string[]} → 202 envelope.
//
// Thresholds:
//   - p(95) < 1000ms  — spike latency tolerance
//   - p(99) < 3000ms  — extreme tail tolerance during spikes
//   - Error rate < 3% — slightly relaxed for spike conditions
//
// Run (manual/on-demand — the load-gate workflow is archived, ci/README.md §2):
//   K6_API_KEY=am_live_… K6_API_BASE=http://localhost:8080 \
//     K6_FROM_EMAIL=sender@verified.example \
//     k6 run load-tests/http/spike-test.js
// =============================================================================

import { check, group, sleep } from 'k6';
import http from 'k6/http';
import { API_KEY, BASE_URL, FROM_EMAIL, apiKeyHeaders, testTags } from './test-options.js';

// ── Test Options ────────────────────────────────────────────────────────────

export const options = {
  stages: [
    { duration: '2m', target: 10 },
    { duration: '10s', target: 200 },
    { duration: '10s', target: 10 },
    { duration: '1m', target: 10 },
    { duration: '10s', target: 200 },
    { duration: '10s', target: 10 },
    { duration: '1m', target: 10 },
    { duration: '30s', target: 0 },
  ],

  thresholds: {
    http_req_duration: ['p(95)<1000', 'p(99)<3000', 'avg<500'],
    http_req_failed: ['rate<0.03'],
    http_reqs: ['rate>50'],
  },

  discardResponseBodies: false,
  tags: testTags('spike-test'),
};

// ── Setup ───────────────────────────────────────────────────────────────────

export function setup() {
  if (!API_KEY) {
    throw new Error(
      'K6_API_KEY is required (X-API-Key: am_… for the target tenant); ' +
        'refusing to run a spike test whose authenticated scenarios cannot succeed'
    );
  }
  return { start_time: Date.now() };
}

// ── Helper Functions ────────────────────────────────────────────────────────

function simulateThinkTime() {
  sleep(0.5 + Math.random() * 1.5);
}

// ── Main Test Scenario ──────────────────────────────────────────────────────

export default function () {
  const vuId = __VU;
  const iter = __ITER;

  // ── 1. Health Check (lightest operation) ──────────────────────────────────
  group('health check', function () {
    const endpoint = Date.now() % 2 === 0 ? 'live' : 'ready';
    const resp = http.get(`${BASE_URL}/health/${endpoint}`, {
      tags: { endpoint: 'health-check' },
    });
    check(resp, {
      'health status is 200': (r) => r.status === 200,
    });
  });

  simulateThinkTime();

  // ── 2. Authenticated probe (X-API-Key) ────────────────────────────────────
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

  simulateThinkTime();

  // ── 3. Email Send (heaviest operation) ────────────────────────────────────
  group('email send', function () {
    const emailPayload = JSON.stringify({
      from: FROM_EMAIL,
      to: [`spike-recipient-${vuId}-${iter}@example.com`],
      subject: `[Spike Test] Surge traffic — VU ${vuId} iteration ${iter}`,
      text: 'Spike test email payload for instantaneous traffic surge measurement.',
      tags: ['spike-test'],
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
