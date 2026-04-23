import { beforeAll, describe, expect, it } from 'vitest';

import { discoverHttpRoutes, isLikelyPublicRoute, materializeDynamicPath } from '../support/discovery';
import { assertServiceReachable, serviceBaseUrl } from '../support/env';
import { buildRequestInit, requestWithTimeout } from '../support/http';

const SAFE_ERROR_STATUSES = new Set([400, 401, 403, 404, 405, 409, 410, 413, 415, 422, 429]);

const serviceRoutes = (await discoverHttpRoutes()).filter((route) => route.service.startsWith('rust-'));
const services = [...new Set(serviceRoutes.map((route) => route.service))];

beforeAll(async () => {
  expect(serviceRoutes.length).toBeGreaterThan(0);
  for (const service of services) {
    const baseUrl = serviceBaseUrl(service);
    expect(baseUrl, `Missing base URL for ${service}`).toBeTruthy();
    if (baseUrl) {
      await assertServiceReachable(service, baseUrl);
    }
  }
});

describe('rust service route guardrails', () => {
  for (const route of serviceRoutes) {
    const label = `${route.service} ${route.method} ${route.path}`;

    it(`${label} fails safely for unauthenticated malformed requests`, async () => {
      const baseUrl = serviceBaseUrl(route.service);
      expect(baseUrl, `Missing base URL for ${route.service}`).toBeTruthy();
      if (!baseUrl) {
        return;
      }

      const path = materializeDynamicPath(route.path);
      const url = new URL(path, baseUrl).toString();
      const response = await requestWithTimeout(url, buildRequestInit(route.method, true));

      expect(response.status).toBeLessThan(500);

      if (!isLikelyPublicRoute(route)) {
        expect(SAFE_ERROR_STATUSES.has(response.status), `${label} should be protected`).toBe(true);
      }
    });

    it(`${label} resists token confusion and traversal probes`, async () => {
      const baseUrl = serviceBaseUrl(route.service);
      expect(baseUrl, `Missing base URL for ${route.service}`).toBeTruthy();
      if (!baseUrl) {
        return;
      }

      const path = materializeDynamicPath(route.path).replace(/\/$/, '');
      const hostilePath = `${path}/..%2F..%2Finternal`;
      const url = new URL(hostilePath, baseUrl);
      url.searchParams.set('probe', '%00');

      const response = await requestWithTimeout(url.toString(), {
        ...buildRequestInit(route.method, true),
        headers: {
          authorization: 'Bearer almost-correct-token',
          'x-api-key': 'almost-correct-token',
          'content-type': 'application/json',
        },
      });

      expect(response.status).toBeLessThan(500);
      if (!isLikelyPublicRoute(route)) {
        expect(response.status).toBeGreaterThanOrEqual(400);
      }
    });
  }
});
