import { beforeAll, describe, expect, it } from 'vitest';

import { assertServiceReachable, serviceBaseUrl } from '../support/env';
import { requestWithTimeout } from '../support/http';

const apiBaseUrl = serviceBaseUrl('api-server');
const billingBaseUrl = serviceBaseUrl('billing');

function uniqueEmail(): string {
  return `e2e-billing-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@example.com`;
}

async function jsonRequest(baseUrl: string, path: string, init: RequestInit) {
  const url = new URL(path, baseUrl).toString();
  return requestWithTimeout(url, {
    ...init,
    headers: {
      'content-type': 'application/json',
      ...(init.headers ?? {}),
    },
  });
}

describe.sequential('billing + webhook fail-first suite', () => {
  let authToken = '';
  let tenantId = '';

  beforeAll(async () => {
    expect(apiBaseUrl, 'E2E_API_BASE_URL is required').toBeTruthy();
    expect(billingBaseUrl, 'E2E_BILLING_BASE_URL is required').toBeTruthy();

    if (!apiBaseUrl || !billingBaseUrl) {
      return;
    }

    await assertServiceReachable('api-server', apiBaseUrl);
    await assertServiceReachable('billing', billingBaseUrl);

    const email = uniqueEmail();
    const password = 'ApexMail!Billing1234';

    await jsonRequest(apiBaseUrl, '/v1/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        company_name: 'E2E Billing Tenant',
        email,
        name: 'E2E Billing Owner',
        password,
        plan: 'free',
      }),
    });

    const login = await jsonRequest(apiBaseUrl, '/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });

    expect(login.status).toBe(200);
    const loginPayload = login.json as { token?: string; user?: { tenant_id?: string } } | undefined;
    authToken = loginPayload?.token ?? '';
    tenantId = loginPayload?.user?.tenant_id ?? '';

    expect(authToken.length).toBeGreaterThan(0);
    expect(tenantId.length).toBeGreaterThan(0);
  });

  it('rejects unauthenticated billing/admin routes', async () => {
    if (!billingBaseUrl) {
      throw new Error('Missing E2E_BILLING_BASE_URL');
    }

    const protectedRoutes: Array<{ method: string; path: string }> = [
      { method: 'GET', path: '/api/billing/usage' },
      { method: 'GET', path: '/api/billing/subscription' },
      { method: 'GET', path: '/api/admin/tenants' },
      { method: 'POST', path: '/api/billing/checkout' },
    ];

    for (const route of protectedRoutes) {
      const response = await jsonRequest(billingBaseUrl, route.path, {
        method: route.method,
        body: route.method === 'POST' ? JSON.stringify({}) : undefined,
      });

      expect(response.status, `${route.method} ${route.path}`).toBe(401);
    }
  });

  it('blocks unsafe redirect urls for checkout and portal', async () => {
    if (!billingBaseUrl) {
      throw new Error('Missing E2E_BILLING_BASE_URL');
    }

    const headers = {
      authorization: `Bearer ${authToken}`,
      'x-tenant-id': tenantId,
    };

    const evilHost = await jsonRequest(billingBaseUrl, '/api/billing/checkout', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        priceId: 'price_e2e_fake',
        successUrl: 'https://evil-apexmail.ee/success',
        cancelUrl: 'https://apexmail.ee/cancel',
      }),
    });
    expect(evilHost.status).toBe(400);

    const punycode = await jsonRequest(billingBaseUrl, '/api/billing/portal', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        returnUrl: 'https://xn--80ak6aa92e.com/return',
      }),
    });
    expect(punycode.status).toBe(400);
  });

  it('enforces webhook signature and payload integrity', async () => {
    if (!billingBaseUrl) {
      throw new Error('Missing E2E_BILLING_BASE_URL');
    }

    const missingSig = await jsonRequest(billingBaseUrl, '/webhooks/stripe', {
      method: 'POST',
      body: JSON.stringify({ id: 'evt_missing_sig' }),
    });
    expect(missingSig.status).toBe(400);

    const invalidJson = await requestWithTimeout(new URL('/webhooks/stripe', billingBaseUrl).toString(), {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'stripe-signature': 'v1=fake',
      },
      body: '{"id":',
    });

    expect(invalidJson.status).toBe(400);
  });

  it('authenticated billing endpoints avoid 5xx under malformed inputs', async () => {
    if (!billingBaseUrl) {
      throw new Error('Missing E2E_BILLING_BASE_URL');
    }

    const headers = {
      authorization: `Bearer ${authToken}`,
      'x-tenant-id': tenantId,
    };

    const targets: Array<{ method: string; path: string; body?: unknown }> = [
      { method: 'GET', path: '/api/billing/usage' },
      { method: 'GET', path: '/api/billing/subscription' },
      { method: 'GET', path: '/api/billing/invoices?limit=2&offset=0' },
      { method: 'GET', path: '/api/plans' },
      { method: 'POST', path: '/api/billing/alerts', body: { thresholds: [] } },
    ];

    for (const target of targets) {
      const response = await jsonRequest(billingBaseUrl, target.path, {
        method: target.method,
        headers,
        body: target.body ? JSON.stringify(target.body) : undefined,
      });

      expect(response.status, `${target.method} ${target.path}`).toBeLessThan(500);
      expect(response.status, `${target.method} ${target.path} should not be treated as unauthenticated`).not.toBe(401);
    }
  });
});
