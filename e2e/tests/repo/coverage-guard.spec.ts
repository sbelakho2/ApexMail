import { describe, expect, it } from 'vitest';

import { discoverSurfaces, isLikelyPublicRoute, materializeDynamicPath } from '../support/discovery';

describe('coverage guardrails', () => {
  it('has no duplicate backend route records', async () => {
    const { httpRoutes } = await discoverSurfaces();
    const keySet = new Set<string>();

    for (const route of httpRoutes) {
      const key = `${route.service}|${route.method}|${route.path}`;
      expect(keySet.has(key), `duplicate route record found: ${key}`).toBe(false);
      keySet.add(key);
    }

    expect(keySet.size).toBe(httpRoutes.length);
  });

  it('materializes every dynamic path to a concrete request path', async () => {
    const { httpRoutes } = await discoverSurfaces();

    for (const route of httpRoutes) {
      const concrete = materializeDynamicPath(route.path);
      expect(concrete.startsWith('/'), `materialized path is invalid for ${route.path}`).toBe(true);
      expect(concrete.includes(':')).toBe(false);
    }
  });

  it('classifies routes into public or protected for fail-first sweeps', async () => {
    const { httpRoutes } = await discoverSurfaces();

    const publicCount = httpRoutes.filter((route) => isLikelyPublicRoute(route)).length;
    const protectedCount = httpRoutes.length - publicCount;

    expect(publicCount).toBeGreaterThan(0);
    expect(protectedCount).toBeGreaterThan(0);
  });
});
