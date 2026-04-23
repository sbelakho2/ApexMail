import { beforeAll, describe, expect, it } from 'vitest';

import { assertServiceReachable, serviceBaseUrl } from '../support/env';
import { requestWithTimeout } from '../support/http';

type LoginPayload = {
  token: string;
  user: {
    id: string;
    tenant_id: string;
    email: string;
    role: string;
  };
};

const apiBaseUrl = serviceBaseUrl('api-server');

function randomEmail(tag: string): string {
  const seed = `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  return `e2e-${tag}-${seed}@example.com`;
}

async function jsonRequest(path: string, init: RequestInit): Promise<ReturnType<typeof requestWithTimeout>> {
  if (!apiBaseUrl) {
    throw new Error('E2E_API_BASE_URL is missing for account lifecycle tests');
  }

  const url = new URL(path, apiBaseUrl).toString();
  return requestWithTimeout(url, {
    ...init,
    headers: {
      'content-type': 'application/json',
      ...(init.headers ?? {}),
    },
  });
}

beforeAll(async () => {
  expect(apiBaseUrl, 'E2E_API_BASE_URL is required').toBeTruthy();
  if (apiBaseUrl) {
    await assertServiceReachable('api-server', apiBaseUrl);
  }
});

describe.sequential('account and auth lifecycle (fail-first)', () => {
  const email = randomEmail('account');
  const password = 'ApexMail!Pass1234';
  let token = '';
  let apiKeyId = '';

  it('rejects invalid registration payloads', async () => {
    const response = await jsonRequest('/v1/auth/register', {
      method: 'POST',
      body: JSON.stringify({ company_name: '', email: 'bad', name: '', password: 'weak', plan: 'free' }),
    });

    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(response.status).toBeLessThan(500);
  });

  it('registers a new account', async () => {
    const response = await jsonRequest('/v1/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        company_name: 'E2E Tenant',
        email,
        name: 'E2E Owner',
        password,
        plan: 'free',
      }),
    });

    expect([201, 202]).toContain(response.status);
  });

  it('handles duplicate registration idempotently', async () => {
    const response = await jsonRequest('/v1/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        company_name: 'E2E Tenant',
        email,
        name: 'E2E Owner',
        password,
        plan: 'free',
      }),
    });

    expect([201, 202]).toContain(response.status);
  });

  it('rejects bad credentials', async () => {
    const response = await jsonRequest('/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        email,
        password: 'Wrong!Password123',
      }),
    });

    expect([400, 401]).toContain(response.status);
  });

  it('logs in with valid credentials', async () => {
    const response = await jsonRequest('/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        email,
        password,
      }),
    });

    expect(response.status).toBe(200);
    const payload = response.json as LoginPayload | undefined;

    expect(payload?.token).toBeTruthy();
    expect(payload?.user?.tenant_id).toBeTruthy();
    token = payload?.token ?? '';
  });

  it('returns authenticated session for valid bearer', async () => {
    const response = await jsonRequest('/v1/auth/session', {
      method: 'GET',
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    expect(response.status).toBe(200);
    const payload = response.json as { authenticated?: boolean; user?: unknown } | undefined;
    expect(payload?.authenticated).toBe(true);
    expect(payload?.user).toBeTruthy();
  });

  it('creates an api key and then lists it', async () => {
    const create = await jsonRequest('/v1/auth/api-keys', {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        name: 'e2e-key',
        scopes: ['messages:read', 'messages:send'],
      }),
    });

    expect(create.status).toBe(201);
    const createPayload = create.json as { id?: string; key?: string } | undefined;
    expect(createPayload?.id).toBeTruthy();
    expect(createPayload?.key?.startsWith('am_')).toBe(true);
    apiKeyId = createPayload?.id ?? '';

    const list = await jsonRequest('/v1/auth/api-keys', {
      method: 'GET',
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    expect(list.status).toBe(200);
    expect(list.bodyText.includes(apiKeyId)).toBe(true);
  });

  it('revokes created api key', async () => {
    const revoke = await jsonRequest(`/v1/auth/api-keys/${apiKeyId}`, {
      method: 'DELETE',
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    expect(revoke.status).toBe(204);
  });

  it('logs out and rejects invalid refresh', async () => {
    const logout = await jsonRequest('/v1/auth/logout', {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({}),
    });

    expect([200, 204]).toContain(logout.status);

    const refresh = await jsonRequest('/v1/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({
        token: 'invalid-token',
      }),
    });

    expect([400, 401]).toContain(refresh.status);
  });
});
