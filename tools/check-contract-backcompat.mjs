import fs from 'node:fs';
import path from 'node:path';

const currentPath = path.resolve('docs/api-contract-manifest.json');
const baselinePath = path.resolve('docs/migration/baselines/api-contract-manifest.baseline.json');

const current = JSON.parse(fs.readFileSync(currentPath, 'utf8'));
const baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));

function fail(message) {
  console.error(`[contract-backcompat] ${message}`);
  process.exit(1);
}

for (const key of ['frontendRequiredEndpoints', 'backendRoutePatterns']) {
  if (!Array.isArray(current[key]) || !Array.isArray(baseline[key])) {
    fail(`${key} missing from current or baseline manifest`);
  }

  const currentSet = new Set(current[key]);
  const removed = baseline[key].filter((entry) => !currentSet.has(entry));
  if (removed.length > 0) {
    fail(`${key} removed entries detected: ${removed.join(', ')}`);
  }
}

if (typeof current.version !== 'number' || typeof baseline.version !== 'number') {
  fail('version must be numeric in current and baseline manifest');
}

if (current.version < baseline.version) {
  fail(`current version ${current.version} is lower than baseline version ${baseline.version}`);
}

console.log('[contract-backcompat] OK');
