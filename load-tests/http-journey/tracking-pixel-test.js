// ApexMail Tracking Pixel Throughput Test — k6 script
// Targets the REAL tracking-service routes (services/mail-server/crates/
// tracking-service/src/routes/mod.rs):
//
//   GET {pixel_path}/:tracking_id   — canonical pixel (default /o/:id)
//   GET /o.gif?t=:tracking_id       — alternative pixel form
//   GET {click_path}/:tracking_id   — click redirect (default /c/:id)
//
// Both pixel forms ALWAYS answer 200 with the transparent GIF (even for
// unknown tokens — email clients must render), and the click route always
// redirects (3xx) to the configured target/fallback. The previous URLs
// (/v1/tracking/pixel.gif, /v1/tracking/click.gif) do not exist on the
// tracking service and 404'd — the suite could only ever fail (LT-5).
//
// Tracking pixels must handle high throughput with minimal latency since
// every email open generates a request.
//
// Thresholds:
//   - p95 http_req_duration < 200ms  (tracking pixels must be fast)
//   - p99 http_req_duration < 500ms
//   - Error rate < 0.1%
//
// Run (manual/on-demand — the load-gate workflow is archived, ci/README.md §2):
//   K6_TRACKING_BASE=http://localhost:3001 k6 run tracking-pixel-test.js

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// ── Custom metrics ───────────────────────────────────────────────────────────
const trackingDuration = new Trend('tracking_duration');
const errorRate = new Rate('error_rate');
const totalRequests = new Counter('total_requests');

// ── Configuration ────────────────────────────────────────────────────────────
// The tracking service is its own origin (compose service `tracking`, port
// 3001; production: track.apexmail.ee), NOT the api-server.
const TRACKING_BASE = __ENV.K6_TRACKING_BASE || 'http://localhost:3001';

// ── Options ──────────────────────────────────────────────────────────────────
export const options = {
  stages: [
    { duration: '30s', target: 500 },     // Quick ramp to 500 VUs
    { duration: '1m', target: 1000 },      // Ramp to 1000 VUs
    { duration: '2m', target: 2000 },      // Ramp to 2000 VUs (production burst)
    { duration: '3m', target: 2000 },      // Sustain at 2000 VUs
    { duration: '1m', target: 500 },       // Ramp down
    { duration: '30s', target: 0 },        // Cool-down
  ],
  thresholds: {
    http_req_duration: ['p(95)<200', 'p(99)<500'],
    http_req_failed: ['rate<0.001'],
    tracking_duration: ['p(95)<200'],
    error_rate: ['rate<0.001'],
  },
  tags: {
    test: 'tracking-pixel-throughput',
    service: 'tracking-service',
  },
};

// ── Helpers ──────────────────────────────────────────────────────────────────
function syntheticTrackingId() {
  // The click handler requires 10..4096 chars; the pixel accepts anything.
  return `msg-${__VU}-${Date.now()}-${Math.random().toString(36).substring(2, 10)}`;
}

// ── Main test function ───────────────────────────────────────────────────────
export default function () {
  group('Tracking', function () {
    const trackingId = syntheticTrackingId();
    const roll = Math.random();

    let url;
    let isClick = false;
    if (roll < 0.6) {
      // 60%: canonical path pixel
      url = `${TRACKING_BASE}/o/${trackingId}`;
    } else if (roll < 0.8) {
      // 20%: the /o.gif?t= alternative pixel form
      url = `${TRACKING_BASE}/o.gif?t=${encodeURIComponent(trackingId)}`;
    } else {
      // 20%: click redirect
      isClick = true;
      url = `${TRACKING_BASE}/c/${trackingId}?r=${encodeURIComponent('https://example.com/landing-page')}`;
    }

    const res = http.get(url, {
      tags: {
        tracking_type: isClick ? 'click' : 'open',
      },
    });

    trackingDuration.add(res.timings.duration);
    totalRequests.add(1);
    errorRate.add(res.status >= 400);

    check(res, {
      'tracking response status is expected': (r) =>
        isClick ? (r.status === 301 || r.status === 302) : r.status === 200,
      'open pixel response is a GIF': (r) =>
        isClick || r.headers['Content-Type'] === 'image/gif' || r.headers['content-type'] === 'image/gif',
      'tracking duration < 200ms': (r) => r.timings.duration < 200,
    });
  });

  // Minimal think time: pixels arrive in campaign bursts.
  sleep(Math.random() * 0.1 + 0.01); // 10–110ms between requests
}
