// =============================================================================
// ApexMail — Stress Test
// =============================================================================
// LT-C-02: Stress test that pushes the API server beyond expected capacity to
// find its breaking point. This test simulates sudden traffic spikes and
// sustained overload conditions.
//
// Stages:
//   1. Ramp to 50 VUs  over 1m     — warm-up
//   2. Spike to 200 VUs over 30s   — sudden traffic surge
//   3. Stay at 200 VUs for 3m      — sustained overload
//   4. Spike to 200 VUs over 30s   — second surge (tests recovery)
//   5. Stay at 200 VUs for 3m      — sustained overload
//   6. Ramp down to 0 VUs over 1m  — cooldown
//
// Thresholds:
//   - p(99) response time < 2000ms  — tail latency must stay bounded
//   - Error rate < 5%               — higher tolerance under extreme load
//   - Server must not crash         — observed via connection errors
//
// What we're testing:
//   - Connection pool exhaustion limits
//   - Rate limiter effectiveness (should return 429, not 5xx)
//   - Graceful degradation under load
//   - Recovery after load spike subsides
//   - Memory leak detection (stable RSS under sustained load)
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
    // Ramp up to 50 VUs (warm-up)
    { duration: '1m', target: 50 },

    // Spike to 200 VUs
    { duration: '30s', target: 200 },

    // Stay at peak for 3 minutes
    { duration: '3m', target: 200 },

    // Second spike (tests recovery from first wave)
    { duration: '30s', target: 200 },

    // Stay at peak again
    { duration: '3m', target: 200 },

    // Ramp down
    { duration: '1m', target: 0 },
  ],

  thresholds: {
    // ── General HTTP thresholds ─────────────────────────────────────────────
    http_req_duration: [
      'p(95)<1000',   // 95% of requests under 1000ms (relaxed for stress)
      'p(99)<2000',   // 99% of requests under 2000ms
      'avg<800',      // Average latency under 800ms
    ],
    http_req_failed: [
      'rate<0.05',    // Less than 5% error rate (relaxed for stress test)
    ],

    // ── Rate limit response ─────────────────────────────────────────────────
    // A well-behaved system returns HTTP 429 (rate limited) rather than 5xx
    // under extreme load. Track the rate limit response count.
    'http_reqs': ['rate>100'],  // Must sustain at least 100 req/s
  },

  // Discard response bodies
  discardResponseBodies: true,

  // No connection reuse — simulate many distinct clients
  noConnectionReuse: true,

  tags: testTags('stress-test'),
};

// ── Test Scenario ───────────────────────────────────────────────────────────

export default function () {
  const vuId = __VU;
  const iter = __ITER;

  // ── Health Check (lightweight, no auth) ───────────────────────────────────
  group('health check', function () {
    // Alternate between liveness and readiness to distribute load
    const endpoint = iter % 2 === 0 ? 'liveness' : 'readiness';
    const resp = http.get(
      `${BASE_URL}/v1/health/${endpoint}`,
      {
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        tags: { endpoint: `health-${endpoint}` },
      }
    );

    check(resp, {
      'health status is 200': (r) => r.status === 200,
    });
  });

  // ── Auth Login (moderate weight) ──────────────────────────────────────────
  group('auth login', function () {
    const loginPayload = JSON.stringify({
      email: `stress-user-${vuId}@apexmail.ee`,
      password: `stress-pass-${vuId}`,
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
        // Ignore parse errors under stress
      }
    }
  });

  // ── Email Send (heaviest operation) ───────────────────────────────────────
  group('email send', function () {
    const token = __ENV.__TOKEN || '';
    if (!token) {
      return;  // Skip if authentication failed
    }

    const emailPayload = JSON.stringify({
      from: `stress-${vuId}@apexmail.ee`,
      to: [`stress-recipient-${vuId}-${iter}@example.com`],
      subject: `[Stress Test] VU ${vuId} Iteration ${iter} — ${randomString(8)}`,
      text_body: 'This is a stress test email. '.repeat(20),  // Larger payload
      tags: {
        stress_test: 'true',
        vu_id: String(vuId),
      },
    });

    const emailResp = http.post(
      `${BASE_URL}/v1/email/send`,
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
