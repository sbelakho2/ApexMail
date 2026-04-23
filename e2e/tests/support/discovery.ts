import fs from 'node:fs/promises';
import path from 'node:path';

import { repoRoot } from './env';
import type { HttpMethod, RouteRecord, UiRouteRecord } from './types';

const IGNORED_DIRS = new Set(['node_modules', '.git', '.turbo', 'target', 'dist', 'coverage']);
const STANDALONE_HTTP_CRATES = new Set(['devex-service', 'enterprise', 'observability-service']);
const UI_BASELINE_MANIFEST_PATH = path.join(repoRoot, 'docs/development/ui-baseline-manifest.json');

type UiBaselineManifest = {
  surfaces: Array<{
    id: string;
    routes: Array<{
      path: string;
    }>;
  }>;
};

async function walkFiles(dirPath: string): Promise<string[]> {
  const results: string[] = [];
  let entries: Array<import('node:fs').Dirent> = [];

  try {
    entries = await fs.readdir(dirPath, { withFileTypes: true });
  } catch {
    return results;
  }

  for (const entry of entries) {
    if (entry.name.startsWith('.')) {
      continue;
    }

    const abs = path.join(dirPath, entry.name);

    if (entry.isDirectory()) {
      if (!IGNORED_DIRS.has(entry.name)) {
        const nested = await walkFiles(abs);
        results.push(...nested);
      }
      continue;
    }

    if (entry.isFile()) {
      results.push(abs);
    }
  }

  return results;
}

function workspacePath(absPath: string): string {
  return path.relative(repoRoot, absPath).split(path.sep).join('/');
}

function normalizePath(routePath: string): string {
  const value = routePath.trim();
  if (!value) {
    return '/';
  }

  const startsWithSlash = value.startsWith('/');
  const normalized = value.replace(/\/+/g, '/').replace(/\/\/+/, '/');
  const withLeading = startsWithSlash ? normalized : `/${normalized}`;
  return withLeading.replace(/\/\/{2,}/g, '/');
}

function joinPath(prefix: string, routePath: string): string {
  const left = normalizePath(prefix);
  const right = normalizePath(routePath);

  if (right === '/') {
    return left;
  }
  if (left === '/') {
    return right;
  }

  return `${left.replace(/\/$/, '')}/${right.replace(/^\//, '')}`;
}

function extractTsMethodsAndPaths(content: string, receiver: 'router' | 'app'): Array<{ method: HttpMethod; path: string }> {
  const matches: Array<{ method: HttpMethod; path: string }> = [];
  const re = new RegExp(`${receiver}\\.(get|post|put|patch|delete)\\(\\s*['\"]([^'\"]+)['\"]`, 'g');

  for (const match of content.matchAll(re)) {
    const method = match[1].toUpperCase() as HttpMethod;
    const routePath = normalizePath(match[2]);
    matches.push({ method, path: routePath });
  }

  return matches;
}

function parseRustMethods(chain: string): HttpMethod[] {
  const methods: HttpMethod[] = [];
  if (/\bget\(/.test(chain)) methods.push('GET');
  if (/\bpost\(/.test(chain)) methods.push('POST');
  if (/\bput\(/.test(chain)) methods.push('PUT');
  if (/\bpatch\(/.test(chain)) methods.push('PATCH');
  if (/\bdelete\(/.test(chain)) methods.push('DELETE');
  return [...new Set(methods)];
}

function parseRustRoutes(content: string): Array<{ path: string; methods: HttpMethod[] }> {
  const lines = content.split(/\r?\n/);
  const records: Array<{ path: string; methods: HttpMethod[] }> = [];

  for (let i = 0; i < lines.length; i += 1) {
    if (!lines[i].includes('.route(')) {
      continue;
    }

    const window = lines.slice(i, i + 8).join(' ');
    const pathMatch = window.match(/\.route\(\s*"([^"]+)"\s*,\s*([^;]+?)\)/);
    if (!pathMatch) {
      continue;
    }

    const routePath = normalizePath(pathMatch[1]);
    const methods = parseRustMethods(pathMatch[2]);
    if (methods.length === 0) {
      continue;
    }

    records.push({ path: routePath, methods });
  }

  const seen = new Set<string>();
  const deduped: Array<{ path: string; methods: HttpMethod[] }> = [];

  for (const record of records) {
    const key = `${record.path}|${record.methods.join(',')}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    deduped.push(record);
  }

  return deduped;
}

async function discoverBillingRoutes(): Promise<RouteRecord[]> {
  const appFile = path.join(repoRoot, 'apps/billing/src/app.ts');
  const routesDir = path.join(repoRoot, 'apps/billing/src/routes');
  const records: RouteRecord[] = [];

  const appContent = await fs.readFile(appFile, 'utf8');
  const mountPrefixByFunction = new Map<string, string>();

  for (const match of appContent.matchAll(/app\.route\(\s*'([^']+)'\s*,\s*([A-Za-z0-9_]+)\(ctx\)\s*\)/g)) {
    mountPrefixByFunction.set(match[2], normalizePath(match[1]));
  }

  for (const route of extractTsMethodsAndPaths(appContent, 'app')) {
    records.push({
      service: 'billing',
      method: route.method,
      path: route.path,
      sourceFile: workspacePath(appFile),
      moduleName: 'app',
    });
  }

  const routeFiles = (await walkFiles(routesDir)).filter((file) => file.endsWith('.ts') && !file.endsWith('index.ts'));

  for (const routeFile of routeFiles) {
    const content = await fs.readFile(routeFile, 'utf8');
    const fnMatch = content.match(/export function\s+([A-Za-z0-9_]+)\s*\(/);
    const fnName = fnMatch ? fnMatch[1] : undefined;
    const mountPrefix = fnName ? mountPrefixByFunction.get(fnName) : undefined;
    const fallbackPrefix = `/api/${path.basename(routeFile, '.ts')}`;
    const prefix = mountPrefix ?? normalizePath(fallbackPrefix);

    for (const route of extractTsMethodsAndPaths(content, 'router')) {
      records.push({
        service: 'billing',
        method: route.method,
        path: joinPath(prefix, route.path),
        sourceFile: workspacePath(routeFile),
        moduleName: fnName,
      });
    }
  }

  return records;
}

async function discoverApiServerRoutes(): Promise<RouteRecord[]> {
  const appFile = path.join(repoRoot, 'services/mail-server/crates/api-server/src/app.rs');
  const routesRoot = path.join(repoRoot, 'services/mail-server/crates/api-server/src/routes');
  const records: RouteRecord[] = [];
  const content = await fs.readFile(appFile, 'utf8');

  for (const route of parseRustRoutes(content)) {
    for (const method of route.methods) {
      records.push({
        service: 'api-server',
        method,
        path: route.path,
        sourceFile: workspacePath(appFile),
        moduleName: 'app',
      });
    }
  }

  const nests = [...content.matchAll(/\.nest\(\s*"([^"]+)"\s*,\s*routes::([A-Za-z0-9_:]+)::router\(\)\s*\)/g)];

  for (const nest of nests) {
    const prefix = normalizePath(nest[1]);
    const modulePath = nest[2].replace(/::/g, '/');
    const moduleFile = path.join(routesRoot, `${modulePath}.rs`);

    let routeContent = '';
    try {
      routeContent = await fs.readFile(moduleFile, 'utf8');
    } catch {
      continue;
    }

    const moduleRoutes = parseRustRoutes(routeContent);
    for (const moduleRoute of moduleRoutes) {
      for (const method of moduleRoute.methods) {
        records.push({
          service: 'api-server',
          method,
          path: joinPath(prefix, moduleRoute.path),
          sourceFile: workspacePath(moduleFile),
          moduleName: modulePath,
        });
      }
    }
  }

  return records;
}

async function discoverStandaloneRustServiceRoutes(): Promise<RouteRecord[]> {
  const cratesRoot = path.join(repoRoot, 'services/mail-server/crates');
  const files = (await walkFiles(cratesRoot)).filter((file) => file.endsWith('/src/routes.rs'));
  const records: RouteRecord[] = [];

  for (const file of files) {
    if (file.includes('/api-server/')) {
      continue;
    }

    const parts = file.split(path.sep);
    const cratesIndex = parts.lastIndexOf('crates');
    const crateName = cratesIndex >= 0 ? parts[cratesIndex + 1] : 'unknown';
    if (!STANDALONE_HTTP_CRATES.has(crateName)) {
      continue;
    }
    const service = `rust-${crateName}`;

    const content = await fs.readFile(file, 'utf8');
    const routes = parseRustRoutes(content);

    for (const route of routes) {
      for (const method of route.methods) {
        records.push({
          service,
          method,
          path: route.path,
          sourceFile: workspacePath(file),
          moduleName: 'routes',
        });
      }
    }
  }

  return records;
}

function dedupeAndSortRoutes(records: RouteRecord[]): RouteRecord[] {
  const seen = new Set<string>();
  const deduped: RouteRecord[] = [];

  for (const record of records) {
    const key = `${record.service}|${record.method}|${record.path}`;
    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    deduped.push(record);
  }

  return deduped.sort((a, b) => {
    const service = a.service.localeCompare(b.service);
    if (service !== 0) return service;
    const pathCmp = a.path.localeCompare(b.path);
    if (pathCmp !== 0) return pathCmp;
    return a.method.localeCompare(b.method);
  });
}

function deriveUiRoutePath(relativePagePath: string): string {
  const withoutPage = relativePagePath.replace(/(^|\/)page\.tsx$/, '');
  if (!withoutPage || withoutPage === '.' || withoutPage === '/') {
    return '/';
  }

  const segments = withoutPage
    .split('/')
    .filter((segment) => segment.length > 0)
    .filter((segment) => !(segment.startsWith('(') && segment.endsWith(')')))
    .map((segment) => {
      if (segment.startsWith('[[...') && segment.endsWith(']]')) {
        return `:${segment.slice(5, -2)}*`;
      }
      if (segment.startsWith('[...') && segment.endsWith(']')) {
        return `:${segment.slice(4, -1)}*`;
      }
      if (segment.startsWith('[') && segment.endsWith(']')) {
        return `:${segment.slice(1, -1)}`;
      }
      return segment;
    });

  const joined = segments.join('/');
  return joined ? `/${joined}` : '/';
}

async function discoverManifestUiRoutes(): Promise<UiRouteRecord[]> {
  const manifest = JSON.parse(await fs.readFile(UI_BASELINE_MANIFEST_PATH, 'utf8')) as UiBaselineManifest;
  const sourceFile = workspacePath(UI_BASELINE_MANIFEST_PATH);

  return manifest.surfaces.flatMap((surface) => {
    return surface.routes.map((route) => ({
      app: surface.id,
      path: normalizePath(route.path),
      sourceFile,
    }));
  });
}

export async function discoverUiRoutes(): Promise<UiRouteRecord[]> {
  const appsRoot = path.join(repoRoot, 'apps');
  const files = await walkFiles(appsRoot);

  const pageFiles = files.filter(
    (file) => file.endsWith('/page.tsx') && file.includes('/src/app/'),
  );

  const routes: UiRouteRecord[] = [];

  for (const file of pageFiles) {
    const relApps = workspacePath(file);
    const parts = relApps.split('/');
    const appName = parts[1];

    const appRoot = path.join(repoRoot, 'apps', appName, 'src/app');
    const relToAppRoot = path.relative(appRoot, file).split(path.sep).join('/');
    const routePath = deriveUiRoutePath(relToAppRoot);

    routes.push({
      app: appName,
      path: routePath,
      sourceFile: relApps,
    });
  }

  const manifestRoutes = await discoverManifestUiRoutes();
  const discoveredApps = new Set(routes.map((route) => route.app));

  for (const route of manifestRoutes) {
    if (discoveredApps.has(route.app)) {
      continue;
    }
    routes.push(route);
  }

  const seen = new Set<string>();
  const deduped: UiRouteRecord[] = [];
  for (const route of routes) {
    const key = `${route.app}|${route.path}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    deduped.push(route);
  }

  return deduped.sort((a, b) => {
    const appCmp = a.app.localeCompare(b.app);
    if (appCmp !== 0) return appCmp;
    return a.path.localeCompare(b.path);
  });
}

export async function discoverHttpRoutes(): Promise<RouteRecord[]> {
  const [billing, apiServer, rustServices] = await Promise.all([
    discoverBillingRoutes(),
    discoverApiServerRoutes(),
    discoverStandaloneRustServiceRoutes(),
  ]);

  return dedupeAndSortRoutes([...billing, ...apiServer, ...rustServices]);
}

export async function discoverSurfaces(): Promise<{ httpRoutes: RouteRecord[]; uiRoutes: UiRouteRecord[] }> {
  const [httpRoutes, uiRoutes] = await Promise.all([
    discoverHttpRoutes(),
    discoverUiRoutes(),
  ]);

  return { httpRoutes, uiRoutes };
}

export function materializeDynamicPath(rawPath: string): string {
  const normalized = normalizePath(rawPath);
  return normalized
    .replace(/:[A-Za-z0-9_]+\*/g, 'sample/path')
    .replace(/:[A-Za-z0-9_]+/g, 'sample')
    .replace(/\/\/{2,}/g, '/');
}

export function isLikelyPublicRoute(route: RouteRecord): boolean {
  const pathValue = route.path;

  if (route.service === 'api-server') {
    return (
      pathValue.startsWith('/health')
      || pathValue === '/verify-email'
      || pathValue.startsWith('/v1/auth/login')
      || pathValue.startsWith('/v1/auth/register')
      || pathValue.startsWith('/v1/auth/signup')
      || pathValue.startsWith('/v1/auth/reset-password')
      || pathValue.startsWith('/v1/auth/verify-email')
      || pathValue.startsWith('/v1/auth/forgot-password')
      || pathValue.startsWith('/v1/auth/logout')
      || pathValue.startsWith('/v1/auth/sso')
      || pathValue.startsWith('/v1/auth/session')
      || pathValue.startsWith('/v1/auth/csrf')
      || pathValue.startsWith('/api/auth')
      || pathValue.startsWith('/api/csrf')
      || pathValue.startsWith('/v1/ses')
    );
  }

  if (route.service === 'billing') {
    return pathValue === '/health' || pathValue === '/ready' || pathValue.startsWith('/webhooks');
  }

  if (route.service.startsWith('rust-')) {
    return (
      pathValue === '/health'
      || pathValue === '/readiness'
      || pathValue.startsWith('/health/')
      || pathValue.startsWith('/sso/login/')
      || pathValue === '/sso/validate'
    );
  }

  return false;
}
