import { describe, expect, it } from 'vitest';

import { discoverSurfaces } from '../support/discovery';

describe('repo surface discovery', () => {
  it('discovers broad backend and frontend route surfaces', async () => {
    const { httpRoutes, uiRoutes } = await discoverSurfaces();

    expect(httpRoutes.length).toBeGreaterThan(40);
    expect(uiRoutes.length).toBeGreaterThan(5);
  });

  it('discovers critical high-risk backend endpoints', async () => {
    const { httpRoutes } = await discoverSurfaces();
    const keys = new Set(httpRoutes.map((route) => `${route.service}|${route.method}|${route.path}`));

    const critical = [
      'api-server|POST|/v1/auth/login',
      'api-server|POST|/v1/auth/register',
      'api-server|POST|/v1/messages',
      'api-server|GET|/health/live',
      'api-server|POST|/v1/webhooks/:id/test',
      'billing|POST|/webhooks/stripe',
      'billing|POST|/api/billing/checkout',
      'billing|POST|/api/billing/portal',
      'billing|GET|/api/admin/tenants',
    ];

    for (const item of critical) {
      expect(keys.has(item), `missing critical route: ${item}`).toBe(true);
    }
  });

  it('discovers critical ui entry paths', async () => {
    const { uiRoutes } = await discoverSurfaces();
    const keys = new Set(uiRoutes.map((route) => `${route.app}|${route.path}`));

    const critical = [
      'web|/',
      'control-plane|/',
    ];

    for (const item of critical) {
      expect(keys.has(item), `missing critical ui route: ${item}`).toBe(true);
    }
  });
});
