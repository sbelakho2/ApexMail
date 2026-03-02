import fs from 'node:fs';
import path from 'node:path';

const manifestPath = path.resolve('docs/api-contract-manifest.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

const routeFiles = [];
function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full);
    } else if (entry.isFile() && entry.name === 'route.ts') {
      routeFiles.push(full);
    }
  }
}

for (const base of ['apps/web/src/app/api', 'apps/control-plane/src/app/api']) {
  if (fs.existsSync(base)) walk(base);
}

const normalizeFromFile = (file) => {
  const idx = file.indexOf('/src/app/api/');
  const suffix = file.slice(idx + '/src/app/api'.length).replace(/\/route\.ts$/, '');
  return suffix === '' ? '/api' : `/api${suffix}`;
};

const routePaths = routeFiles.map(normalizeFromFile).sort();

const patterns = [
  ...(manifest.frontendRequiredEndpoints || []),
  ...(manifest.backendRoutePatterns || []),
];

const toRegex = (pattern) => {
  const escaped = pattern
    .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`);
};

const patternRegexes = patterns.map((pattern) => ({ pattern, regex: toRegex(pattern) }));

const uncovered = [];
for (const route of routePaths) {
  const covered = patternRegexes.some(({ regex }) => regex.test(route));
  if (!covered) uncovered.push(route);
}

const report = {
  routeCount: routePaths.length,
  patternCount: patterns.length,
  uncoveredCount: uncovered.length,
  uncovered,
};

console.log(JSON.stringify(report, null, 2));
