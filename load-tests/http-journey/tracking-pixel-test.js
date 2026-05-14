// ApexMail Tracking Pixel Throughput Test — k6 script
// Targets the tracking-pixel endpoint (1×1 transparent GIF) used for open tracking.
// Tracking pixels must handle high throughput with minimal latency since every
// email open generates a request.
//
// This test simulates burst traffic from a large email campaign where thousands
// of recipients open emails simultaneously.
//
// Thresholds:
//   - p95 http_req_duration < 200ms  (tracking pixels must be fast)
//   - p99 http_req_duration < 500ms
//   - Error rate < 0.1%  (tracking pixels should virtually never fail)
//   - Throughput target: > 5000 req/s sustained
//
// Usage:
//   k6 run tracking-pixel-test.js
//   K6_API_BASE=http://staging.apexmail.ee k6 run tracking-pixel-test.js

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// ── Custom metrics ───────────────────────────────────────────────────────────
const trackingDuration = new Trend('tracking_duration');
const errorRate = new Rate('error_rate');
const totalRequests = new Counter('total_requests');

// ── Configuration ────────────────────────────────────────────────────────────
const API_BASE = __ENV.K6_API_BASE || 'http://localhost:3000';

// Tracking pixel campaign simulation parameters
const CAMPAIGN_IDS = Array.from({ length: 100 }, (_, i) => `campaign-${i + 1}`);
const RECIPIENT_IDS = Array.from({ length: 10000 }, (_, i) => `recip-${i + 1}`);

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

// ── Helper: generate deterministic but varied tracking pixel URL ────────────
function generatePixelUrl() {
  const campaignId = CAMPAIGN_IDS[Math.floor(Math.random() * CAMPAIGN_IDS.length)];
  const recipientId = RECIPIENT_IDS[Math.floor(Math.random() * RECIPIENT_IDS.length)];
  const messageId = `msg-${__VU}-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;

  // Tracking pixel endpoint — returns a 1×1 transparent GIF
  return `${API_BASE}/v1/tracking/pixel.gif?campaign=${campaignId}&recipient=${recipientId}&message=${messageId}`;
}

// ── Helper: generate deterministic but varied tracking link URL ─────────────
function generateTrackingLinkUrl() {
  const campaignId = CAMPAIGN_IDS[Math.floor(Math.random() * CAMPAIGN_IDS.length)];
  const recipientId = RECIPIENT_IDS[Math.floor(Math.random() * RECIPIENT_IDS.length)];
  const linkId = `link-${Math.random().toString(36).substring(2, 10)}`;
  const redirectTo = 'https://example.com/landing-page';

  return `${API_BASE}/v1/tracking/click.gif?campaign=${campaignId}&recipient=${recipientId}&link=${linkId}&url=${encodeURIComponent(redirectTo)}`;
}

// ── Main test function ───────────────────────────────────────────────────────
export default function () {
  group('Tracking Pixel', function () {
    // 80% of traffic: standard tracking pixel (open tracking)
    // 20% of traffic: tracking link click (click tracking)
    const isTrackingLink = Math.random() < 0.2;

    const url = isTrackingLink ? generateTrackingLinkUrl() : generatePixelUrl();

    const res = http.get(url, {
      tags: {
        tracking_type: isTrackingLink ? 'click' : 'open',
      },
    });

    trackingDuration.add(res.timings.duration);
    totalRequests.add(1);
    errorRate.add(res.status >= 400);

    check(res, {
      'tracking pixel status is 200 or 301': (r) => r.status === 200 || r.status === 301,
      'tracking pixel response is GIF (or redirect)': (r) => {
        // Tracking pixel returns 200 with a GIF; click tracking returns 301 redirect
        if (r.status === 301) return true;
        return r.headers['Content-Type'] === 'image/gif' ||
               r.headers['content-type'] === 'image/gif';
      },
      'tracking duration < 200ms': (r) => r.timings.duration < 200,
    });
  });

  // ── Think time: minimal burst simulation ──────────────────────────────────
  // Tracking pixels arrive in bursts (many recipients opening simultaneously),
  // so think time is very short with high variance.
  sleep(Math.random() * 0.1 + 0.01); // 10–110ms between requests
}

// ── Teardown ─────────────────────────────────────────────────────────────────
export function teardown() {
  console.log(`Tracking pixel load test complete. Total requests: ${totalRequests.name}`);
}
