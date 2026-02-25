import { describe, expect, test } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

interface ApiContractManifest {
  version: number;
  canonicalCustomerPrefix: string;
  gatewayCompatibilityPrefixes: string[];
  frontendRequiredEndpoints: string[];
  backendRoutePatterns: string[];
}

const ROOT = path.join(__dirname, '../../../..');
const MANIFEST_PATH = path.join(ROOT, 'docs', 'api-contract-manifest.json');
const WEB_SRC = path.join(ROOT, 'apps', 'web', 'src');
const CONTROL_PLANE_SRC = path.join(ROOT, 'apps', 'control-plane', 'src');

function readManifest(): ApiContractManifest {
  const raw = fs.readFileSync(MANIFEST_PATH, 'utf-8');
  return JSON.parse(raw) as ApiContractManifest;
}

function listFiles(dir: string): string[] {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { recursive: true })
    .filter((entry): entry is string => typeof entry === 'string')
    .filter((entry) => /\.(ts|tsx|js|mjs)$/.test(entry))
    .map((entry) => path.join(dir, entry));
}

function collectEndpoints(files: string[]): Set<string> {
  const endpointRegex = /(['"`])(\/v1\/[A-Za-z0-9_\-\/:?=&.*]+|\/api\/v1\/[A-Za-z0-9_\-\/:?=&.*]+)\1/g;
  const endpoints = new Set<string>();

  for (const file of files) {
    const source = fs.readFileSync(file, 'utf-8');
    let match: RegExpExecArray | null;
    while ((match = endpointRegex.exec(source)) !== null) {
      const value = match[2];
      if (value) endpoints.add(value.split('?')[0]);
    }
  }

  return endpoints;
}

function endpointMatchesPattern(endpoint: string, pattern: string): boolean {
  const regex = new RegExp(`^${pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\*/g, '.*')}$`);
  return regex.test(endpoint);
}

describe('API contract manifest', () => {
  test('manifest exists and declares canonical customer prefix', () => {
    expect(fs.existsSync(MANIFEST_PATH)).toBe(true);
    const manifest = readManifest();
    expect(manifest.canonicalCustomerPrefix).toBe('/v1');
    expect(manifest.frontendRequiredEndpoints.length).toBeGreaterThan(0);
  });

  test('web app no longer uses /api/v1 prefix directly', () => {
    const files = listFiles(WEB_SRC);
    const endpoints = collectEndpoints(files);
    const legacyApiPrefix = [...endpoints].filter((endpoint) => endpoint.startsWith('/api/v1/'));
    expect(legacyApiPrefix).toEqual([]);
  });

  test('required frontend endpoints are represented in source usage or proxy routes', () => {
    const manifest = readManifest();
    const endpoints = collectEndpoints([
      ...listFiles(WEB_SRC),
      ...listFiles(CONTROL_PLANE_SRC),
    ]);

    for (const requiredEndpoint of manifest.frontendRequiredEndpoints) {
      const wildcardPrefix = requiredEndpoint.endsWith('*') ? requiredEndpoint.slice(0, -1) : null;
      const present = wildcardPrefix
        ? [...endpoints].some((endpoint) => endpoint.startsWith(wildcardPrefix))
        : endpoints.has(requiredEndpoint);

      expect(present, `Missing frontend endpoint usage for ${requiredEndpoint}`).toBe(true);
    }
  });

  test('every required frontend endpoint maps to a backend route pattern', () => {
    const manifest = readManifest();

    for (const requiredEndpoint of manifest.frontendRequiredEndpoints) {
      const matches = manifest.backendRoutePatterns.some((pattern) => endpointMatchesPattern(requiredEndpoint, pattern));
      expect(matches, `No backend contract pattern for ${requiredEndpoint}`).toBe(true);
    }
  });
});
