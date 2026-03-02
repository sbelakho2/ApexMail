import fs from 'node:fs';
import path from 'node:path';

const manifest = JSON.parse(
  fs.readFileSync(path.resolve('docs/api-contract-manifest.json'), 'utf8'),
);

function fail(message) {
  console.error(`[consumer-contract-test] ${message}`);
  process.exit(1);
}

const required = manifest.frontendRequiredEndpoints || [];
const patterns = manifest.backendRoutePatterns || [];

const toRegex = (pattern) => {
  const escaped = pattern
    .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`);
};

const regexes = patterns.map((p) => ({ pattern: p, regex: toRegex(p) }));

const uncovered = [];
for (const endpoint of required) {
  const ok = regexes.some(({ regex }) => regex.test(endpoint));
  if (!ok) uncovered.push(endpoint);
}

if (uncovered.length > 0) {
  fail(`frontend required endpoints not covered by backend patterns: ${uncovered.join(', ')}`);
}

console.log('[consumer-contract-test] OK');
