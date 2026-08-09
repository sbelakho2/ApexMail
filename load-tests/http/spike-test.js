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
// Thresholds:
//   - p(95) < 1000ms  — spike latency tolerance
//   - p(99) < 3000ms  — extreme tail tolerance during spikes
//   - Error rate < 3% — slightly relaxed for spike conditions
//
// Key metrics to watch:
//   - http_req_duration trend — does latency spike then recover?
//   - http_req_failed — do errors concentrate during spike transitions?
//   - http_reqs — does throughput drop during recovery periods (connection pool drain)?
// =============================================================================

import { check, group } from 'k6';
import http from 'k6/http';
import { sleep } from 'k6';
import { testTags } from './test-options.js';

// ── Configuration ───────────────────────────────────────────────────────────

const BASE_URL = __ENV.K6_API_BASE || 'http://localhost:3000';

// ── Test Options ────────────────────────────────────────────────────────────

export const options = {
  stages: [
    // ── Stage 1: Baseline ──────────────────────────────────────────────────
    { duration: '2m', target: 10 },

    // ── Stage 2: Spike 1 ───────────────────────────────────────────────────
    { duration: '10s', target: 200 },

    // ── Stage 3: Recovery 1 ────────────────────────────────────────────────
    { duration: '10s', target: 10 },

    // ── Stage 4: Baseline 2 ────────────────────────────────────────────────
    { duration: '1m', target: 10 },

    // ── Stage 5: Spike 2 ───────────────────────────────────────────────────
    { duration: '10s', target: 200 },

    // ── Stage 6: Recovery 2 ────────────────────────────────────────────────
    { duration: '10s', target: 10 },

    // ── Stage 7: Baseline 3 ────────────────────────────────────────────────
    { duration: '1m', target: 10 },

    // ── Stage 8: Cooldown ──────────────────────────────────────────────────
    { duration: '30s', target: 0 },
  ],

  thresholds: {
    http_req_duration: [
      'p(95)<1000',   // 95% of requests under 1000ms (even during spikes)
      'p(99)<3000',   // 99% of requests under 3000ms
      'avg<500',      // Average latency under 500ms
    ],
    http_req_failed: [
      'rate<0.03',    // Less than 3% error rate (relaxed for spike conditions)
    ],
    // During spikes, the request rate should increase significantly.
    // If it plateaus, the system is saturated.
    http_reqs: [
      'rate>50',      // Must sustain at least 50 req/s average
    ],
  },

  discardResponseBodies: true,

  tags: testTags('spike-test'),
};

// ── Helper Functions ────────────────────────────────────────────────────────

function simulateThinkTime() {
  // Simulate realistic user think time between actions
  // During spike, reduce think time (users are impatient)
  sleep(0.5 + Math.random() * 1.5);
}

// ── Main Test Scenario ──────────────────────────────────────────────────────

export default function () {
  const vuId = __VU;

  // ── 1. Health Check (lightest operation) ──────────────────────────────────
  group('health check', function () {
    // During spikes, alternate endpoints to distribute load
    const endpoint = Date.now() % 2 === 0 ? 'live' : 'ready';
    const resp = http.get(
      `${BASE_URL}/health/${endpoint}`,
      {
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        tags: { endpoint: 'health-check' },
      }
    );

    check(resp, {
      'health status is 200': (r) => r.status === 200,
    });
  });

  simulateThinkTime();

  // ── 2. Auth Login ─────────────────────────────────────────────────────────
  group('auth login', function () {
    const loginPayload = JSON.stringify({
      email: `spike-user-${vuId}@apexmail.ee`,
      password: `spike-pass-${vuId}`,
    });

    const loginResp = http.post(
      `${BASE_URL}/v1/auth/login`,
      loginPayload,
      {
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        tags: { endpoint: 'auth-login' },
      }
    );

    check(loginResp, {
      'auth status is 200 or 429': (r) => r.status === 200 || r.status === 429,
      'auth not 5xx': (r) => r.status < 500,
    });

    if (loginResp.status === 200) {
      try {
        __ENV.__TOKEN = JSON.parse(loginResp.body).token;
      } catch {
        // Ignore parse errors during spikes
      }
    }
  });

  simulateThinkTime();

  // ── 3. Email Send ─────────────────────────────────────────────────────────
  group('email send', function () {
    const token = __ENV.__TOKEN || '';

    const emailPayload = JSON.stringify({
      from: `spike-${vuId}@apexmail.ee`,
      to: [`spike-recipient-${vuId}-${Date.now()}@example.com`],
      subject: `[Spike Test] Surge traffic — VU ${vuId} at ${Date.now()}`,
      text_body: 'Spike test email payload for instantaneous traffic surge measurement.',
      tags: {
        spike_test: 'true',
        vu_id: String(vuId),
      },
    });

    const emailResp = http.post(
      `${BASE_URL}/v1/messages`,
      emailPayload,
      {
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        tags: { endpoint: 'email-send' },
      }
    );

    check(emailResp, {
      'email status is 200, 202, or 429': (r) =>
        r.status === 200 || r.status === 202 || r.status === 429,
      'email not 5xx': (r) => r.status < 500,
    });
  });
}
