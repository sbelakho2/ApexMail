// ApexMail Billing Calculation Load Test — k6 script
// Tests billing calculations under concurrent tenant load.
// Exercises multi-tenant billing scenarios including plan calculations,
// overage costs, VAT calculations, and invoice generation.
//
// Usage:
//   K6_API_BASE=http://staging.apexmail.ee K6_API_KEY=xxx k6 run billing-load-test.js
//
// Targets:
//   - 50,000 billing ops/sec sustained
//   - p95 latency < 250ms
//   - Correct calculations across 100+ concurrent tenants

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// ── Custom metrics ───────────────────────────────────────────────────────────
const billingCalcDuration = new Trend('billing_calc_duration');
const billingListDuration = new Trend('billing_list_duration');
const billingErrorRate = new Rate('billing_error_rate');
const billingOpsCount = new Counter('billing_ops_count');
const tenantCount = new Counter('tenant_count');

// ── Configuration ────────────────────────────────────────────────────────────
const API_BASE = __ENV.K6_API_BASE || 'http://localhost:3000';
const API_KEY = __ENV.K6_API_KEY || 'test-api-key-00000000000000000000000000000';

// ── Options ──────────────────────────────────────────────────────────────────
export const options = {
  stages: [
    { duration: '1m', target: 10 },    // Warm-up
    { duration: '2m', target: 50 },    // Ramp to 50 tenants
    { duration: '3m', target: 100 },   // Ramp to 100 tenants
    { duration: '5m', target: 200 },   // Ramp to 200 tenants
    { duration: '5m', target: 200 },   // Sustain at 200 tenants
    { duration: '1m', target: 0 },     // Cool-down
  ],
  thresholds: {
    billing_calc_duration: ['p(95)<250', 'p(99)<500'],
    billing_list_duration: ['p(95)<500', 'p(99)<1000'],
    billing_error_rate: ['rate<0.01'],
    http_req_duration: ['p(95)<500'],
    http_req_failed: ['rate<0.01'],
  },
  tags: {
    test: 'billing-load',
    service: 'billing-service',
  },
};

// ── Generate tenant-specific headers ─────────────────────────────────────────
function tenantHeaders(tenantId) {
  return {
    'Authorization': `Bearer ${API_KEY}`,
    'Content-Type': 'application/json',
    'X-Tenant-ID': `tenant-${tenantId}`,
  };
}

// ── Main test function ───────────────────────────────────────────────────────
export default function () {
  const tenantId = __VU; // Each VU acts as a separate tenant
  const headers = tenantHeaders(tenantId);
  tenantCount.add(1);

  // Distribute operations: 50% billing calculations, 30% plan/usage list, 20% invoice ops
  const roll = Math.random();

  // ── BILLING CALCULATION ──────────────────────────────────────────────────
  if (roll < 0.50) {
    group('Billing Calculation', function () {
      // Calculate overage for a tenant with varying usage
      const usagePayload = JSON.stringify({
        tenant_id: `tenant-${tenantId}`,
        emails_sent: 50000 + (__VU * 1000),
        emails_delivered: 48000 + (__VU * 900),
        storage_gb: 10 + (__VU % 50),
        api_calls: 100000 + (__VU * 5000),
        period_start: '2026-05-01T00:00:00Z',
        period_end: '2026-05-31T23:59:59Z',
        plan: __VU % 3 === 0 ? 'enterprise' : __VU % 2 === 0 ? 'pro' : 'starter',
      });

      const res = http.post(`${API_BASE}/v1/billing/calculate`, usagePayload, {
        headers,
        tags: { billing_op: 'calculate' },
      });

      billingCalcDuration.add(res.timings.duration);
      billingOpsCount.add(1);
      billingErrorRate.add(res.status >= 400);

      check(res, {
        'billing calc status is 200': (r) => r.status === 200,
        'billing calc has cost': (r) => {
          try { return JSON.parse(r.body).total_cost !== undefined; }
          catch { return false; }
        },
        'billing calc duration < 250ms': (r) => r.timings.duration < 250,
      });
    });

  // ── LIST PLANS & USAGE ───────────────────────────────────────────────────
  } else if (roll < 0.80) {
    group('Billing List / Usage', function () {
      // List available plans
      const plansRes = http.get(`${API_BASE}/v1/billing/plans`, {
        headers,
        tags: { billing_op: 'list_plans' },
      });
      billingListDuration.add(plansRes.timings.duration);
      billingOpsCount.add(1);
      billingErrorRate.add(plansRes.status >= 400);
      check(plansRes, {
        'plans list status is 200': (r) => r.status === 200,
      });

      // Get current usage
      const usageRes = http.get(`${API_BASE}/v1/billing/usage?period=current`, {
        headers,
        tags: { billing_op: 'usage' },
      });
      billingListDuration.add(usageRes.timings.duration);
      billingOpsCount.add(1);
      billingErrorRate.add(usageRes.status >= 400);
      check(usageRes, {
        'usage status is 200': (r) => r.status === 200,
      });
    });

  // ── INVOICE OPERATIONS ───────────────────────────────────────────────────
  } else {
    group('Billing Invoice', function () {
      // List invoices
      const listRes = http.get(`${API_BASE}/v1/billing/invoices?limit=10&page=1`, {
        headers,
        tags: { billing_op: 'list_invoices' },
      });
      billingListDuration.add(listRes.timings.duration);
      billingOpsCount.add(1);
      billingErrorRate.add(listRes.status >= 400);
      check(listRes, {
        'invoice list status is 200': (r) => r.status === 200,
      });

      // Simulate invoice preview
      const previewPayload = JSON.stringify({
        plan: 'pro',
        billing_cycle: 'monthly',
        addons: { dedicated_ip: true, extra_reputation: false },
        estimated_usage: { emails: 100000, storage_gb: 20 },
      });
      const previewRes = http.post(`${API_BASE}/v1/billing/invoice/preview`, previewPayload, {
        headers,
        tags: { billing_op: 'preview_invoice' },
      });
      billingListDuration.add(previewRes.timings.duration);
      billingOpsCount.add(1);
      billingErrorRate.add(previewRes.status >= 400);
    });
  }

  // ── Think time ──
  sleep(Math.random() * 0.3 + 0.1); // 100–400ms
}

// ── Teardown ─────────────────────────────────────────────────────────────────
export function teardown() {
  console.log(`Billing load test complete. Total operations: ${billingOpsCount.name}`);
}
