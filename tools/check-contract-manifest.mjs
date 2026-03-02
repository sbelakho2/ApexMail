import fs from 'node:fs';
import path from 'node:path';

const manifestPath = path.resolve('docs/api-contract-manifest.json');
const raw = fs.readFileSync(manifestPath, 'utf8');
const manifest = JSON.parse(raw);

function fail(message) {
  console.error(`[contract-manifest] ${message}`);
  process.exit(1);
}

function ensureArray(name) {
  if (!Array.isArray(manifest[name])) {
    fail(`${name} must be an array`);
  }
}

if (typeof manifest.version !== 'number' || !Number.isInteger(manifest.version) || manifest.version < 1) {
  fail('version must be an integer >= 1');
}

if (typeof manifest.canonicalCustomerPrefix !== 'string' || !manifest.canonicalCustomerPrefix.startsWith('/')) {
  fail('canonicalCustomerPrefix must be an absolute path prefix');
}

ensureArray('gatewayCompatibilityPrefixes');
ensureArray('frontendRequiredEndpoints');
ensureArray('backendRoutePatterns');

const endpointPattern = /^\/[a-z0-9\-/*._]+$/;

for (const key of ['canonicalCustomerPrefix']) {
  const value = manifest[key];
  if (!endpointPattern.test(value)) {
    fail(`${key} contains invalid characters: ${value}`);
  }
}

for (const key of ['gatewayCompatibilityPrefixes', 'frontendRequiredEndpoints', 'backendRoutePatterns']) {
  for (const value of manifest[key]) {
    if (typeof value !== 'string' || !value.startsWith('/')) {
      fail(`${key} contains non-path value: ${String(value)}`);
    }
    if (!endpointPattern.test(value)) {
      fail(`${key} contains invalid path pattern: ${value}`);
    }
  }
}

console.log('[contract-manifest] OK');
