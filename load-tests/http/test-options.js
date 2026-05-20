// =============================================================================
// ApexMail — Shared k6 Test Options Module
// =============================================================================
// LT-C-02: Common configuration options shared across all HTTP load test
// scripts. Import this module to standardise thresholds, base URLs, and
// environment variable handling.
//
// Usage:
//   import { BASE_URL, COMMON_OPTIONS, THRESHOLDS } from './test-options.js';
//   export const options = {
//     ...COMMON_OPTIONS,
//     thresholds: { ...THRESHOLDS, ...yourCustomThresholds },
//     stages: [...yourStages],
//   };
// =============================================================================

import http from 'k6/http';
import { check, sleep } from 'k6';

// ── Environment ─────────────────────────────────────────────────────────────

/**
 * Base URL for the ApexMail API server.
 * Override with K6_API_BASE environment variable.
 * @type {string}
 */
export const BASE_URL = __ENV.K6_API_BASE || 'http://localhost:3000';

/**
 * API key for authenticated endpoints.
 * Override with K6_API_KEY environment variable.
 * @type {string}
 */
export const API_KEY = __ENV.K6_API_KEY || '';

// ── HTTP Headers ────────────────────────────────────────────────────────────

/**
 * Default headers applied to all requests.
 * @type {Object<string, string>}
 */
export const DEFAULT_HEADERS = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'User-Agent': 'ApexMail-k6-load-test/1.0',
};

/**
 * Headers for authenticated requests (includes Bearer token).
 * @param {string} token - JWT bearer token
 * @returns {Object<string, string>} Headers object
 */
export function authHeaders(token) {
  return {
    ...DEFAULT_HEADERS,
    'Authorization': `Bearer ${token}`,
  };
}

/**
 * Headers for API-key-based authentication.
 * @returns {Object<string, string>} Headers object
 */
export function apiKeyHeaders() {
  return {
    ...DEFAULT_HEADERS,
    'Authorization': `Bearer ${API_KEY}`,
  };
}

// ── Threshold Definitions ───────────────────────────────────────────────────

/**
 * Standard performance thresholds for load testing.
 * These are designed to gate CI/CD — if exceeded, the test fails.
 *
 * | Threshold | Value | Rationale |
 * |-----------|-------|-----------|
 * | p(95) < 500ms | Hard fail | Core SLO for API response time |
 * | p(99) < 2000ms | Hard fail | Tail latency must stay bounded |
 * | Failed rate < 1% | Hard fail | Error budget for load tests |
 * | p(95) < 200ms (health) | Hard fail | Health endpoints must be cheap |
 *
 * @type {Object<string, string>}
 */
export const THRESHOLDS = {
  // ── General HTTP thresholds ───────────────────────────────────────────────
  http_req_duration: [
    'p(95)<500',    // 95% of requests must complete within 500ms
    'p(99)<2000',   // 99% of requests must complete within 2000ms
    'avg<300',      // Average latency must stay under 300ms
  ],
  http_req_failed: [
    'rate<0.01',    // Error rate must be below 1%
  ],

  // ── Per-endpoint custom metrics (set by individual scripts) ───────────────
  // These are placeholders; individual scripts override with endpoint-specific
  // thresholds. Example:
  //   auth_login_duration: ['p(95)<500'],
  //   email_send_duration: ['p(95)<500'],
  //   health_duration: ['p(95)<200'],
};

// ── Common Options ──────────────────────────────────────────────────────────

/**
 * Base options object that all tests should extend.
 * Includes common settings like DNS cache, TLS, and summary export.
 *
 * @type {Object}
 */
export const COMMON_OPTIONS = {
  // ── Execution ─────────────────────────────────────────────────────────────
  // Discard response bodies after processing to reduce memory pressure
  discardResponseBodies: true,

  // ── Networking ────────────────────────────────────────────────────────────
  // Disable keep-alive to simulate real-world connection patterns
  // (comment out to test with connection reuse)
  // noConnectionReuse: true,

  // DNS cache TTL — match realistic DNS resolution intervals
  dns: {
    ttl: '30s',
    select: 'roundRobin',
    policy: 'preferIPv4',
  },

  // TLS configuration
  tls: {
    // Accept self-signed certificates for development environments
    insecureSkipTLSVerify: __ENV.K6_INSECURE === 'true',
  },

  // ── Thresholds ────────────────────────────────────────────────────────────
  thresholds: THRESHOLDS,

  // ── Summary ───────────────────────────────────────────────────────────────
  // Export summary to JSON for post-processing and baseline comparison
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(50)', 'p(95)', 'p(99)', 'count'],
};

// ── Helper Functions ────────────────────────────────────────────────────────

/**
 * Generates a unique email address for testing.
 * @param {number} vuId - Virtual User ID (__VU)
 * @param {number} iteration - Iteration number
 * @returns {string} Unique email address
 */
export function uniqueEmail(vuId, iteration) {
  const ts = Date.now();
  return `test-${vuId}-${iteration}-${ts}@apexmail-loadtest.ee`;
}

/**
 * Generates a random string of specified length.
 * @param {number} length - Length of the string
 * @returns {string} Random alphanumeric string
 */
export function randomString(length = 10) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

/**
 * Sleep for a random duration within a range (uniform distribution).
 * @param {number} min - Minimum sleep time in seconds
 * @param {number} max - Maximum sleep time in seconds
 */
export function randomSleep(min = 0.5, max = 2.5) {
  const duration = min + Math.random() * (max - min);
  sleep(duration);
}

/**
 * Tags for identifying test runs in metrics.
 * @param {string} testName - Name of the test scenario
 * @returns {Object<string, string>} Tags object
 */
export function testTags(testName) {
  return {
    test: testName,
    run_id: `k6-${Date.now()}`,
    environment: __ENV.K6_ENV || 'local',
  };
}
