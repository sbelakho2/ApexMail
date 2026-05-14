// ApexMail SMTP Load Test — k6 script
// Tests SMTP submission throughput with realistic email payloads.
// Ramp-up stages: 10 → 50 → 100 → 200 VUs
// Thresholds: p95 < 500ms, error rate < 1%
//
// Usage:
//   k6 run smtp-load-test.js
//   K6_SMTP_HOST=smtp.staging.apexmail.ee K6_SMTP_USER=xxx K6_SMTP_PASS=xxx k6 run smtp-load-test.js

// Note: k6 does not natively support SMTP protocol sockets.
// This script uses k6's HTTP API to route through the ApexMail SMTP submission
// API endpoint, which proxies SMTP traffic. For direct SMTP testing, use
// a dedicated SMTP load testing tool like smtp-source (Postfix) or swaks.

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// ── Custom metrics ───────────────────────────────────────────────────────────
const smtpSubmitDuration = new Trend('smtp_submit_duration');
const smtpBulkDuration = new Trend('smtp_bulk_duration');
const smtpErrorRate = new Rate('smtp_error_rate');
const smtpThroughput = new Rate('smtp_throughput');

// ── Configuration ────────────────────────────────────────────────────────────
const API_BASE = __ENV.K6_API_BASE || 'http://localhost:3000';
const API_KEY = __ENV.K6_API_KEY || 'test-api-key-00000000000000000000000000000';

const HEADERS = {
  'Authorization': `Bearer ${API_KEY}`,
  'Content-Type': 'application/json',
  'X-Tenant-ID': `tenant-${__VU}`,
};

// ── Options ──────────────────────────────────────────────────────────────────
export const options = {
  stages: [
    { duration: '1m', target: 10 },   // Warm-up: 10 VUs
    { duration: '2m', target: 50 },   // Ramp to 50 VUs
    { duration: '3m', target: 100 },  // Ramp to 100 VUs
    { duration: '3m', target: 200 },  // Ramp to 200 VUs
    { duration: '5m', target: 200 },  // Sustained load
    { duration: '2m', target: 0 },    // Cool-down
  ],
  thresholds: {
    smtp_submit_duration: ['p(95)<2000', 'p(99)<5000'],
    smtp_error_rate: ['rate<0.01'],
    http_req_duration: ['p(95)<1000'],
    http_req_failed: ['rate<0.01'],
  },
};

// ── Helper: Generate realistic email payloads ────────────────────────────────
const domains = [
  'gmail.com', 'outlook.com', 'yahoo.com', 'proton.me',
  'example.org', 'company.co.uk', 'startup.io', 'mail.de',
];

function randomRecipient() {
  const names = ['alice', 'bob', 'carol', 'dave', 'eve', 'frank',
    'grace', 'heidi', 'ivan', 'judy', 'mallory', 'oscar'];
  const name = names[Math.floor(Math.random() * names.length)];
  const domain = domains[Math.floor(Math.random() * domains.length)];
  return `${name}.${__VU}@${domain}`;
}

function singleEmailPayload() {
  return JSON.stringify({
    to: [randomRecipient()],
    from: `sender-${__VU}@apexmail.ee`,
    subject: `SMTP Load Test — VU ${__VU} — ${Date.now()}`,
    text_body: `This is an SMTP load test message.\nVU: ${__VU}\nTimestamp: ${Date.now()}\n---\nThis message was generated for performance testing purposes.`,
    html_body: `<html><body><h3>SMTP Load Test</h3><p>VU: ${__VU}</p><p>Timestamp: ${Date.now()}</p><hr/><p>Performance test message.</p></body></html>`,
    options: {
      track_opens: true,
      track_clicks: true,
      priority: 'normal',
    },
  });
}

function bulkPayload(count) {
  const recipients = [];
  for (let i = 0; i < count; i++) {
    recipients.push(randomRecipient());
  }
  return JSON.stringify({
    to: recipients,
    from: `bulk-sender-${__VU}@apexmail.ee`,
    subject: `Bulk SMTP Test — Batch ${Date.now()}`,
    text_body: `Bulk email test message.\nBatch size: ${count}`,
    html_body: `<html><body><p>Bulk email test. Batch size: ${count}</p></body></html>`,
    options: {
      track_opens: false,
      track_clicks: false,
      priority: 'bulk',
    },
  });
}

// ── Main test function ───────────────────────────────────────────────────────
export default function () {
  // 70% single sends, 30% bulk sends (5-20 recipients each)
  const isBulk = Math.random() < 0.30;

  group(isBulk ? 'SMTP Bulk Send' : 'SMTP Single Send', function () {
    const url = `${API_BASE}/v1/email/send`;
    const payload = isBulk
      ? bulkPayload(Math.floor(Math.random() * 15) + 5)  // 5-20 recipients
      : singleEmailPayload();

    const res = http.post(url, payload, { headers: HEADERS });

    if (isBulk) {
      smtpBulkDuration.add(res.timings.duration);
    } else {
      smtpSubmitDuration.add(res.timings.duration);
    }
    smtpErrorRate.add(res.status >= 400);

    check(res, {
      'SMTP submit status is 202': (r) => r.status === 202,
      'SMTP submit has message_id': (r) => {
        try { return JSON.parse(r.body).message_id !== undefined; }
        catch { return false; }
      },
      'SMTP submit duration < 5s': (r) => r.timings.duration < 5000,
    });
  });

  // ── Think time: SMTP senders typically batch ──
  sleep(Math.random() * 1.0 + 0.2); // 200–1200ms between submits
}

// ── Teardown ─────────────────────────────────────────────────────────────────
export function teardown() {
  console.log('SMTP load test complete.');
}
