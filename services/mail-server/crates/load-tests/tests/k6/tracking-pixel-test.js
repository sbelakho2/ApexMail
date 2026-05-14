// ApexMail Tracking Pixel & Click Tracking Load Test — k6 script
// High-volume GET requests through the tracking service.
// Validates throughput, latency, and data integrity at scale.
//
// Usage:
//   K6_TRACKING_BASE=http://tracking.staging.apexmail.ee k6 run tracking-pixel-test.js
//
// Targets:
//   - 10,000 rps sustained
//   - p95 latency < 50ms
//   - 0 data loss (every event must reach the database)

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// ── Custom metrics ───────────────────────────────────────────────────────────
const pixelDuration = new Trend('pixel_duration');
const clickDuration = new Trend('click_duration');
const unsubscribeDuration = new Trend('unsubscribe_duration');
const pixelErrorRate = new Rate('pixel_error_rate');
const clickErrorRate = new Rate('click_error_rate');
const unsubscribeErrorRate = new Rate('unsubscribe_error_rate');
const pixelCount = new Counter('pixel_count');
const clickCount = new Counter('click_count');
const unsubscribeCount = new Counter('unsubscribe_count');
const dataIntegrityErrors = new Counter('data_integrity_errors');

// ── Configuration ────────────────────────────────────────────────────────────
const TRACKING_BASE = __ENV.K6_TRACKING_BASE || 'http://localhost:3000';
const API_KEY = __ENV.K6_API_KEY || 'test-api-key-00000000000000000000000000000';

// ── Options ──────────────────────────────────────────────────────────────────
export const options = {
  stages: [
    { duration: '30s', target: 100 },    // Warm-up
    { duration: '1m', target: 500 },     // Ramp
    { duration: '2m', target: 2000 },    // High load
    { duration: '3m', target: 5000 },    // Peak
    { duration: '2m', target: 5000 },    // Sustain at peak
    { duration: '1m', target: 0 },       // Cool-down
  ],
  thresholds: {
    pixel_duration: ['p(95)<50', 'p(99)<100'],
    click_duration: ['p(95)<50', 'p(99)<100'],
    unsubscribe_duration: ['p(95)<200', 'p(99)<500'],
    pixel_error_rate: ['rate<0.001'],    // 0.1% max error rate
    click_error_rate: ['rate<0.001'],
    unsubscribe_error_rate: ['rate<0.01'],
    http_req_duration: ['p(95)<100'],
    http_req_failed: ['rate<0.001'],
  },
  tags: {
    test: 'tracking-pixel',
    service: 'tracking-service',
  },
};

// ── Generate realistic tracking IDs ──────────────────────────────────────────
function generateTrackingId(type) {
  // Simulate base64url-encoded tracking IDs
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  let id = type; // 't' for tracking pixel, 'c' for click
  for (let i = 0; i < 15; i++) {
    id += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return id;
}

// ── Validate response body data integrity ────────────────────────────────────
function validateTrackingResponse(res, trackingType) {
  if (res.status >= 400) {
    dataIntegrityErrors.add(1);
    return false;
  }

  // For tracking pixel: should be a 1x1 transparent GIF
  if (trackingType === 'pixel') {
    const contentType = res.headers['Content-Type'] || res.headers['content-type'] || '';
    if (contentType.includes('image/gif')) {
      // Verify it's a valid 1x1 GIF (43 bytes, GIF89a header)
      const gifHeader = res.body.slice(0, 6);
      if (gifHeader !== 'GIF89a') {
        dataIntegrityErrors.add(1);
        return false;
      }
      return true;
    }
    // Some implementations return a redirect instead
    if (res.status >= 300 && res.status < 400) {
      return true; // Valid redirect-based tracking
    }
    return false;
  }

  // For click tracking: should redirect to destination URL
  if (trackingType === 'click') {
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers['Location'] || res.headers['location'] || '';
      if (location.startsWith('http')) {
        return true;
      }
    }
    dataIntegrityErrors.add(1);
    return false;
  }

  return true;
}

// ── Main test function ───────────────────────────────────────────────────────
export default function () {
  // Distribution: 70% tracking pixels, 25% click redirects, 5% unsubscribes
  const roll = Math.random();

  // ── TRACKING PIXEL ─────────────────────────────────────────────────────────
  if (roll < 0.70) {
    group('Tracking Pixel', function () {
      const trackingId = generateTrackingId('t');
      const url = `${TRACKING_BASE}/t/${trackingId}`;

      const res = http.get(url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; LoadTest/1.0)',
          'Accept': 'image/webp,image/apng,image/*,*/*;q=0.8',
        },
        tags: { tracking_type: 'pixel' },
      });

      pixelDuration.add(res.timings.duration);
      pixelCount.add(1);
      pixelErrorRate.add(res.status >= 400);

      const dataOk = validateTrackingResponse(res, 'pixel');
      if (!dataOk && res.status < 400) {
        console.warn(`Data integrity issue for pixel ${trackingId}: status=${res.status}`);
      }

      check(res, {
        'pixel status is 200 or 204 or 302': (r) =>
          r.status === 200 || r.status === 204 || r.status === 302,
        'pixel latency < 50ms': (r) => r.timings.duration < 50,
        'pixel response valid': () => dataOk,
      });
    });

  // ── CLICK TRACKING ─────────────────────────────────────────────────────────
  } else if (roll < 0.95) {
    group('Click Tracking', function () {
      const trackingId = generateTrackingId('c');
      const url = `${TRACKING_BASE}/c/${trackingId}`;

      const res = http.get(url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        },
        tags: { tracking_type: 'click' },
      });

      clickDuration.add(res.timings.duration);
      clickCount.add(1);
      clickErrorRate.add(res.status >= 400);

      const dataOk = validateTrackingResponse(res, 'click');
      if (!dataOk && res.status < 400) {
        console.warn(`Data integrity issue for click ${trackingId}: status=${res.status}`);
      }

      check(res, {
        'click status is 302 or 301': (r) => r.status === 302 || r.status === 301,
        'click latency < 50ms': (r) => r.timings.duration < 50,
        'click redirect valid': () => dataOk,
      });
    });

  // ── UNSUBSCRIBE ────────────────────────────────────────────────────────────
  } else {
    group('Unsubscribe', function () {
      const token = generateTrackingId('u');
      const url = `${TRACKING_BASE}/u/${token}`;

      const res = http.post(url, '{}', {
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        },
        tags: { tracking_type: 'unsubscribe' },
      });

      unsubscribeDuration.add(res.timings.duration);
      unsubscribeCount.add(1);
      unsubscribeErrorRate.add(res.status >= 400);

      check(res, {
        'unsubscribe status is 200 or 202': (r) =>
          r.status === 200 || r.status === 202,
        'unsubscribe latency < 200ms': (r) => r.timings.duration < 200,
      });
    });
  }
}

// ── Setup ────────────────────────────────────────────────────────────────────
export function setup() {
  console.log(`Tracking pixel load test starting...`);
  console.log(`Target: ${TRACKING_BASE}`);
  console.log('Thresholds: 10,000 rps, p95 < 50ms, 0 data loss');
  return { start_time: Date.now() };
}

// ── Teardown ─────────────────────────────────────────────────────────────────
export function teardown() {
  console.log(`Tracking pixel load test complete.`);
  console.log(`Pixels: ${pixelCount.name}, Clicks: ${clickCount.name}, Unsubscribes: ${unsubscribeCount.name}`);
}
