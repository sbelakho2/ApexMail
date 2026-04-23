import { beforeAll, describe, expect, it } from 'vitest';

import { assertServiceReachable, serviceBaseUrl } from '../support/env';
import { requestWithTimeout } from '../support/http';

const apiBaseUrl = serviceBaseUrl('api-server');

function randomIdentity(): { email: string; password: string } {
  return {
    email: `e2e-usertype-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@example.com`,
    password: 'ApexMail!Users1234',
  };
}

async function jsonRequest(path: string, init: RequestInit) {
  if (!apiBaseUrl) {
    throw new Error('Missing E2E_API_BASE_URL');
  }

  return requestWithTimeout(new URL(path, apiBaseUrl).toString(), {
    ...init,
    headers: {
      'content-type': 'application/json',
      ...(init.headers ?? {}),
    },
  });
}

describe.sequential('user-type lifecycles (owner + SCIM + admin surfaces)', () => {
  let token = '';
  let scimUserId = '';

  beforeAll(async () => {
    expect(apiBaseUrl, 'E2E_API_BASE_URL is required').toBeTruthy();
    if (!apiBaseUrl) {
      return;
    }

    await assertServiceReachable('api-server', apiBaseUrl);

    const identity = randomIdentity();

    await jsonRequest('/v1/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        company_name: 'E2E UserType Tenant',
        email: identity.email,
        name: 'Owner UserType',
        password: identity.password,
        plan: 'free',
      }),
    });

    const login = await jsonRequest('/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        email: identity.email,
        password: identity.password,
      }),
    });

    expect(login.status).toBe(200);
    const payload = login.json as { token?: string } | undefined;
    token = payload?.token ?? '';
    expect(token.length).toBeGreaterThan(20);
  });

  it('supports SCIM user create/list/update/delete lifecycle', async () => {
    const scimIdentity = randomIdentity();

    const create = await jsonRequest('/v1/scim/Users', {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
        id: 'ignored-by-server',
        userName: scimIdentity.email,
        emails: [{ value: scimIdentity.email, primary: true }],
        active: true,
        name: {
          givenName: 'Scim',
          familyName: 'User',
        },
      }),
    });

    expect(create.status).toBe(201);
    const created = create.json as { id?: string } | undefined;
    scimUserId = created?.id ?? '';
    expect(scimUserId.length).toBeGreaterThan(0);

    const list = await jsonRequest('/v1/scim/Users?count=50&startIndex=1', {
      method: 'GET',
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    expect(list.status).toBe(200);
    expect(list.bodyText.includes(scimUserId)).toBe(true);

    const update = await jsonRequest(`/v1/scim/Users/${scimUserId}`, {
      method: 'PUT',
      headers: {
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
        id: scimUserId,
        userName: scimIdentity.email,
        emails: [{ value: scimIdentity.email, primary: true }],
        active: false,
        name: {
          givenName: 'ScimUpdated',
          familyName: 'User',
        },
      }),
    });

    expect(update.status).toBe(200);

    const remove = await jsonRequest(`/v1/scim/Users/${scimUserId}`, {
      method: 'DELETE',
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    expect(remove.status).toBe(204);
  });

  it('exercises admin/control-plane surfaces with owner token', async () => {
    const targets = [
      '/v1/admin/tenants',
      '/v1/admin/features',
      '/v1/admin/audit',
      '/v1/admin/system/health',
    ];

    for (const path of targets) {
      const response = await jsonRequest(path, {
        method: 'GET',
        headers: {
          authorization: `Bearer ${token}`,
        },
      });

      expect(response.status, path).toBeLessThan(500);
    }
  });

  it('checks impersonation and telemetry endpoints are hardened', async () => {
    const impersonate = await jsonRequest('/v1/auth/impersonate', {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        target_user_id: 'non-existent-user',
      }),
    });

    expect(impersonate.status).toBeGreaterThanOrEqual(400);
    expect(impersonate.status).toBeLessThan(500);

    const telemetry = await jsonRequest('/v1/auth/telemetry', {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        event: 'e2e_test_event',
        metadata: {
          source: 'e2e-suite',
        },
      }),
    });

    expect(telemetry.status).toBeLessThan(500);
  });
});
