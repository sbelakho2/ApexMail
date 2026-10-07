// ApexMail Auth Session Load Test — k6 script
// Targets the REAL session-login flow:
//   1. GET  /v1/auth/csrf   — fetch the signed CSRF token (also sets the
//                             csrf_token cookie in the VU's cookie jar)
//   2. POST /v1/auth/login  — {email, password} with `X-CSRF-Token`; the
//                             server answers a session response
//                             {expires_at, user} and an HttpOnly am_session
//                             cookie. There is no JSON `token` field.
//
// Credentials are provided out-of-band (never committed):
//   K6_LOGIN_EMAIL / K6_LOGIN_PASSWORD
//
// The account must not require interactive MFA (an MFA challenge answers 202
// and needs a TOTP step) and the deployment must not require a KiwiCaptcha
// proof for API clients — load-testing the interactive login path is not
// meaningful otherwise. The script fails the check with a specific message in
// those cases instead of counting them as pass.
//
// Ramp-up stages: 10 → 50 → 100 concurrent users.
//
// Thresholds:
//   - p95 http_req_duration < 500ms
//   - p99 http_req_duration < 1000ms
//   - Error rate < 1%
//
// Run (manual/on-demand — the load-gate workflow is archived, ci/README.md §2):
//   K6_API_BASE=http://localhost:8080 \
//     K6_LOGIN_EMAIL=loadtest@example.com K6_LOGIN_PASSWORD='…' \
//     k6 run auth-load-test.js

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// ── Custom metrics ───────────────────────────────────────────────────────────
const authLoginDuration = new Trend('auth_login_duration');
const errorRate = new Rate('error_rate');
const totalRequests = new Counter('total_requests');

// ── Configuration ────────────────────────────────────────────────────────────
const API_BASE = __ENV.K6_API_BASE || 'http://localhost:3000';
const LOGIN_EMAIL = __ENV.K6_LOGIN_EMAIL || '';
const LOGIN_PASSWORD = __ENV.K6_LOGIN_PASSWORD || '';

const HEADERS = {
  'Content-Type': 'application/json',
};

// ── Options ──────────────────────────────────────────────────────────────────
export const options = {
  stages: [
    { duration: '2m', target: 10 },   // Ramp-up to 10 VUs
    { duration: '3m', target: 50 },   // Ramp-up to 50 VUs
    { duration: '3m', target: 100 },  // Ramp-up to 100 VUs
    { duration: '5m', target: 100 },  // Sustain at 100 VUs
    { duration: '2m', target: 0 },    // Ramp-down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1000'],
    http_req_failed: ['rate<0.01'],
    auth_login_duration: ['p(95)<500'],
    error_rate: ['rate<0.01'],
  },
  tags: {
    test: 'auth-session-load',
    endpoint: 'v1-auth-login',
    service: 'api-server',
  },
};

// ── Setup ────────────────────────────────────────────────────────────────────
export function setup() {
  if (!LOGIN_EMAIL || !LOGIN_PASSWORD) {
    throw new Error(
      'K6_LOGIN_EMAIL and K6_LOGIN_PASSWORD are required: the real login route ' +
        'is a CSRF-protected session flow and cannot be exercised with fake credentials'
    );
  }
  return { start_time: Date.now() };
}

// ── Main test function ───────────────────────────────────────────────────────
export default function () {
  group('Auth Session Login', function () {
    // 1. CSRF: the token from this response must be mirrored in the
    //    X-CSRF-Token header of the login POST; the accompanying cookie is
    //    stored automatically in this VU's cookie jar.
    const csrfRes = http.get(`${API_BASE}/v1/auth/csrf`, {
      headers: HEADERS,
      tags: { endpoint: 'auth-csrf' },
    });
    totalRequests.add(1);
    errorRate.add(csrfRes.status >= 400);
    let csrfToken = '';
    try { csrfToken = JSON.parse(csrfRes.body).token || ''; } catch { csrfToken = ''; }
    check(csrfRes, {
      'csrf status is 200': (r) => r.status === 200,
      'csrf token present': () => csrfToken !== '',
    });

    // 2. Login with the session contract.
    const loginPayload = JSON.stringify({
      email: LOGIN_EMAIL,
      password: LOGIN_PASSWORD,
    });
    const res = http.post(`${API_BASE}/v1/auth/login`, loginPayload, {
      headers: { ...HEADERS, 'X-CSRF-Token': csrfToken },
      tags: { endpoint: 'auth-login' },
    });

    authLoginDuration.add(res.timings.duration);
    totalRequests.add(1);
    errorRate.add(res.status >= 400);

    check(res, {
      'auth login status is 200': (r) => {
        if (r.status === 202) {
          // MFA challenge — the account needs an interactive TOTP step.
          return false;
        }
        return r.status === 200;
      },
      'auth login returns a session (expires_at, user)': (r) => {
        try {
          const body = JSON.parse(r.body);
          return body.expires_at !== undefined && body.user !== undefined;
        } catch {
          return false;
        }
      },
      'auth login duration < 500ms': (r) => r.timings.duration < 500,
    });
  });

  // ── Think time: simulate real user behavior ──
  sleep(Math.random() * 0.5 + 0.1); // 100–600ms between requests
}
