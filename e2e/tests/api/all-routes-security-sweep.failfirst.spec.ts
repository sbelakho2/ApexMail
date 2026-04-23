import { beforeAll, describe, expect, it } from 'vitest';

import { discoverHttpRoutes, isLikelyPublicRoute, materializeDynamicPath } from '../support/discovery';
import { assertServiceReachable, serviceBaseUrl } from '../support/env';
import { buildRequestInit, requestWithTimeout } from '../support/http';
import type { HttpMethod } from '../support/types';

const RUNTIME_SERVICES = new Set([
  'api-server',
  'billing',
  'rust-devex-service',
  'rust-observability-service',
  'rust-enterprise',
]);

const SAFE_ERROR_STATUSES = new Set([400, 401, 403, 404, 405, 409, 410, 413, 415, 422, 429]);
const SAFE_PUBLIC_STATUSES = new Set([200, 201, 202, 204, ...SAFE_ERROR_STATUSES]);

const ALL_METHODS: HttpMethod[] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

const discoveredRoutes = (await discoverHttpRoutes()).filter((route) => RUNTIME_SERVICES.has(route.service));
const discoveredServices = [...new Set(discoveredRoutes.map((route) => route.service))];

function alternateMethod(method: HttpMethod): HttpMethod {
  const value = ALL_METHODS.find((candidate) => candidate !== method);
  return value ?? 'GET';
}

function assertNonPublicStatus(status: number, routeLabel: string): void {
  expect(
    SAFE_ERROR_STATUSES.has(status),
    `${routeLabel} expected protected status, got ${status}`,
  ).toBe(true);
}

function assertPublicStatus(status: number, routeLabel: string): void {
  expect(
    SAFE_PUBLIC_STATUSES.has(status),
    `${routeLabel} expected safe public status, got ${status}`,
  ).toBe(true);
}

beforeAll(async () => {
  expect(discoveredRoutes.length).toBeGreaterThan(0);

  for (const service of discoveredServices) {
    const baseUrl = serviceBaseUrl(service);
    expect(baseUrl, `Missing base URL for service ${service}`).toBeTruthy();
    if (baseUrl) {
      await assertServiceReachable(service, baseUrl);
    }
  }
});

describe('all discovered routes: unauthenticated fail-first security sweep', () => {
  for (const route of discoveredRoutes) {
    const routeLabel = `${route.service} ${route.method} ${route.path}`;

    it(`${routeLabel} never returns 5xx for malformed unauthenticated requests`, async () => {
      const baseUrl = serviceBaseUrl(route.service);
      expect(baseUrl, `Missing base URL for ${route.service}`).toBeTruthy();
      if (!baseUrl) {
        return;
      }

      const concretePath = materializeDynamicPath(route.path);
      const url = new URL(concretePath, baseUrl).toString();
      const response = await requestWithTimeout(url, buildRequestInit(route.method, true));

      expect(response.status).toBeLessThan(500);

      if (isLikelyPublicRoute(route)) {
        assertPublicStatus(response.status, routeLabel);
      } else {
        assertNonPublicStatus(response.status, routeLabel);
      }
    });

    it(`${routeLabel} resists HTTP method confusion`, async () => {
      const baseUrl = serviceBaseUrl(route.service);
      expect(baseUrl, `Missing base URL for ${route.service}`).toBeTruthy();
      if (!baseUrl) {
        return;
      }

      const wrongMethod = alternateMethod(route.method);
      const concretePath = materializeDynamicPath(route.path);
      const url = new URL(concretePath, baseUrl).toString();
      const response = await requestWithTimeout(url, buildRequestInit(wrongMethod, true));

      expect(response.status).toBeGreaterThanOrEqual(400);
      expect(response.status).toBeLessThan(500);
    });

    it(`${routeLabel} resists traversal and null-byte probes`, async () => {
      const baseUrl = serviceBaseUrl(route.service);
      expect(baseUrl, `Missing base URL for ${route.service}`).toBeTruthy();
      if (!baseUrl) {
        return;
      }

      const concretePath = materializeDynamicPath(route.path).replace(/\/$/, '');
      const hostilePath = `${concretePath}/..%2F..%2Fetc%2Fpasswd`;
      const hostileUrl = new URL(hostilePath, baseUrl);
      hostileUrl.searchParams.set('q', '%00');

      const response = await requestWithTimeout(hostileUrl.toString(), buildRequestInit(route.method, true));
      expect(response.status).toBeLessThan(500);
    });
  }
});
