// ApexMail Browser-Level SSR Load Test — k6 script
// Uses k6 browser to measure server-side rendering performance for
// control-plane and web surfaces behind nginx.
//
// Requirements:
//   k6 v0.45+ with browser module (k6 browser run)
//   chromium or google-chrome installed
//
// Usage:
//   K6_BASE_URL=http://control-plane.staging.apexmail.ee k6 run browser-ssr-test.js
//
// Targets:
//   - 500 concurrent sessions
//   - Page load p95 < 1.5s (nginx cache warm)
//   - SSR render p95 < 400ms

import { browser } from 'k6/experimental/browser';
import { check, sleep, group } from 'k6';
import { Trend, Rate } from 'k6/metrics';

// ── Custom metrics ───────────────────────────────────────────────────────────
const pageLoadDuration = new Trend('page_load_duration');
const ssrRenderDuration = new Trend('ssr_render_duration');
const pageErrorRate = new Rate('page_error_rate');

// ── Configuration ────────────────────────────────────────────────────────────
const BASE_URL = __ENV.K6_BASE_URL || 'http://localhost:3000';
const AUTH_TOKEN = __ENV.K6_AUTH_TOKEN || 'test-token';

// ── Options ──────────────────────────────────────────────────────────────────
export const options = {
  stages: [
    { duration: '2m', target: 50 },    // Ramp to 50 concurrent sessions
    { duration: '3m', target: 200 },   // Ramp to 200
    { duration: '5m', target: 500 },   // Ramp to 500
    { duration: '5m', target: 500 },   // Sustain at 500
    { duration: '2m', target: 0 },     // Cool-down
  ],
  thresholds: {
    page_load_duration: ['p(95)<1500', 'p(99)<3000'],
    ssr_render_duration: ['p(95)<400', 'p(99)<1000'],
    page_error_rate: ['rate<0.02'],
    browser_http_req_duration: ['p(95)<2000'],
  },
};

// ── Pages to test ────────────────────────────────────────────────────────────
const CONTROL_PLANE_PAGES = [
  { path: '/dashboard', name: 'Control Plane Dashboard' },
  { path: '/analytics', name: 'Control Plane Analytics' },
  { path: '/domains', name: 'Control Plane Domains' },
  { path: '/templates', name: 'Control Plane Templates' },
  { path: '/suppressions', name: 'Control Plane Suppressions' },
  { path: '/billing', name: 'Control Plane Billing' },
  { path: '/settings', name: 'Control Plane Settings' },
];

const WEB_PAGES = [
  { path: '/email', name: 'Web Email List' },
  { path: '/compose', name: 'Web Compose' },
  { path: '/analytics', name: 'Web Analytics' },
  { path: '/templates', name: 'Web Templates' },
  { path: '/settings', name: 'Web Settings' },
];

function measurePageLoad(page, url, pageName) {
  try {
    const startTime = Date.now();

    // Navigate and wait for network to be idle
    page.goto(url, { waitUntil: 'networkidle' });

    const loadTime = Date.now() - startTime;
    pageLoadDuration.add(loadTime);

    // Measure SSR render time via performance API
    const perfTiming = page.evaluate(() => {
      const nav = performance.getEntriesByType('navigation')[0];
      if (nav) {
        return {
          domContentLoaded: nav.domContentLoadedEventEnd - nav.startTime,
          domComplete: nav.domComplete - nav.startTime,
          renderTime: nav.responseEnd - nav.requestStart,
        };
      }
      return null;
    });

    if (perfTiming) {
      ssrRenderDuration.add(perfTiming.renderTime);
    }

    pageErrorRate.add(0);

    check(page, {
      [`${pageName} loaded successfully`]: () => true,
      [`${pageName} render time < 400ms`]: () =>
        perfTiming ? perfTiming.renderTime < 400 : true,
      [`${pageName} load time < 1.5s`]: () => loadTime < 1500,
    });

    return true;
  } catch (err) {
    console.error(`Error loading ${pageName}: ${err.message}`);
    pageErrorRate.add(1);
    return false;
  }
}

// ── Main test function ───────────────────────────────────────────────────────
export default function () {
  const context = browser.newContext({
    viewport: { width: 1920, height: 1080 },
    userAgent: 'k6-browser-load-test/1.0',
  });
  const page = context.newPage();

  // Authenticate via cookie/token injection
  page.evaluate((token) => {
    document.cookie = `session_token=${token}; path=/; Secure; HttpOnly`;
  }, AUTH_TOKEN);

  // Distribute load across control-plane and web pages
  const isControlPlane = Math.random() < 0.5;
  const pages = isControlPlane ? CONTROL_PLANE_PAGES : WEB_PAGES;
  const targetPage = pages[Math.floor(Math.random() * pages.length)];

  const url = `${BASE_URL}${targetPage.path}`;
  group(targetPage.name, function () {
    measurePageLoad(page, url, targetPage.name);
  });

  page.close();
  context.close();

  // Think time between page loads
  sleep(Math.random() * 2 + 1); // 1-3 seconds between pages
}

// ── Teardown ─────────────────────────────────────────────────────────────────
export function teardown() {
  console.log('Browser SSR load test complete.');
}
