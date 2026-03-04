/**
 * Wiring Verification Tests — Marketing Zola
 *
 * Static analysis tests that verify:
 * 1. Every template island mount has a matching registry entry
 * 2. Every registry entry has a matching template mount
 * 3. All Tera partials referenced in templates exist on disk
 * 4. All Zola content pages have non-empty bodies where expected
 * 5. Security headers file covers required headers
 * 6. Static assets referenced in base.html exist
 * 7. Sitemap lists all content routes
 */

import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

const ZOLA_ROOT = path.resolve(__dirname, '../../../../apps/marketing-zola');
const TEMPLATES_DIR = path.join(ZOLA_ROOT, 'templates');
const ISLANDS_DIR = path.join(ZOLA_ROOT, 'islands/src');
const CONTENT_DIR = path.join(ZOLA_ROOT, 'content');
const STATIC_DIR = path.join(ZOLA_ROOT, 'static');

/* ── Helpers ─────────────────────────────────────────────── */

function findFilesRecursive(dir: string, ext: string): string[] {
  const results: string[] = [];
  if (!fs.existsSync(dir)) return results;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...findFilesRecursive(full, ext));
    } else if (entry.name.endsWith(ext)) {
      results.push(full);
    }
  }
  return results;
}

function extractIslandMounts(templateFiles: string[]): Map<string, string[]> {
  const mounts = new Map<string, string[]>();
  for (const file of templateFiles) {
    const content = fs.readFileSync(file, 'utf-8');
    const re = /data-island="([^"]+)"/g;
    let match;
    while ((match = re.exec(content)) !== null) {
      const key = match[1];
      if (!mounts.has(key)) mounts.set(key, []);
      mounts.get(key)!.push(path.relative(TEMPLATES_DIR, file));
    }
  }
  return mounts;
}

function extractRegistryKeys(hydratePath: string): string[] {
  if (!fs.existsSync(hydratePath)) return [];
  const content = fs.readFileSync(hydratePath, 'utf-8');
  const keys: string[] = [];
  const re = /['"]([a-z][\w-]*)['"]:\s*\(\)\s*=>/g;
  let match;
  while ((match = re.exec(content)) !== null) {
    keys.push(match[1]);
  }
  return keys;
}

function extractTeraIncludes(templateFiles: string[]): Map<string, string[]> {
  const includes = new Map<string, string[]>();
  for (const file of templateFiles) {
    const content = fs.readFileSync(file, 'utf-8');
    const re = /{%\s*include\s+"([^"]+)"\s*%}/g;
    let match;
    while ((match = re.exec(content)) !== null) {
      const partial = match[1];
      if (!includes.has(partial)) includes.set(partial, []);
      includes.get(partial)!.push(path.relative(TEMPLATES_DIR, file));
    }
  }
  return includes;
}

/* ── Test Data ───────────────────────────────────────────── */

let templateFiles: string[];
let islandMounts: Map<string, string[]>;
let registryKeys: string[];
let teraIncludes: Map<string, string[]>;

beforeAll(() => {
  templateFiles = findFilesRecursive(TEMPLATES_DIR, '.html');
  islandMounts = extractIslandMounts(templateFiles);
  registryKeys = extractRegistryKeys(path.join(ISLANDS_DIR, 'hydrate.ts'));
  teraIncludes = extractTeraIncludes(templateFiles);
});

/* ── 1. Island Mount ↔ Registry Parity ───────────────────── */

describe('Island hydration wiring', () => {
  it('every template mount has a registry entry', () => {
    const missing: string[] = [];
    for (const [mount] of islandMounts) {
      if (!registryKeys.includes(mount)) {
        missing.push(mount);
      }
    }
    expect(missing, `Template mounts without registry: ${missing.join(', ')}`).toHaveLength(0);
  });

  it('every registry entry has at least one template mount', () => {
    const orphaned = registryKeys.filter((k) => !islandMounts.has(k));
    expect(orphaned, `Registry entries without mounts: ${orphaned.join(', ')}`).toHaveLength(0);
  });

  it('island count matches between templates and registry', () => {
    expect(islandMounts.size).toBe(registryKeys.length);
  });

  it('each island has a corresponding component file', () => {
    const missing: string[] = [];
    for (const key of registryKeys) {
      // Convert kebab-case to PascalCase to find component file
      const pascal = key
        .split('-')
        .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
        .join('');
      const candidates = [
        path.join(ISLANDS_DIR, `${pascal}.tsx`),
        path.join(ISLANDS_DIR, `${pascal}.ts`),
        // Some components may use the kebab name directly
        path.join(ISLANDS_DIR, `${key}.tsx`),
        path.join(ISLANDS_DIR, `${key}.ts`),
      ];
      if (!candidates.some((c) => fs.existsSync(c))) {
        missing.push(`${key} → expected ${pascal}.tsx`);
      }
    }
    expect(missing, `Islands missing component files: ${missing.join(', ')}`).toHaveLength(0);
  });
});

/* ── 2. Tera Partial Existence ───────────────────────────── */

describe('Tera template partials', () => {
  it('all included partials exist on disk', () => {
    const missing: string[] = [];
    for (const [partial, usedIn] of teraIncludes) {
      const fullPath = path.join(TEMPLATES_DIR, partial);
      if (!fs.existsSync(fullPath)) {
        missing.push(`"${partial}" referenced in ${usedIn.join(', ')}`);
      }
    }
    expect(missing, `Missing partials:\n${missing.join('\n')}`).toHaveLength(0);
  });
});

/* ── 3. Compare Page Content ─────────────────────────────── */

describe('Compare pages have content', () => {
  const competitors = ['sendgrid', 'amazon-ses', 'postmark', 'resend'];

  for (const competitor of competitors) {
    it(`${competitor} has non-empty comparison rows`, () => {
      const mdPath = path.join(CONTENT_DIR, 'compare', competitor, 'index.md');
      expect(fs.existsSync(mdPath), `File exists: ${mdPath}`).toBe(true);
      const content = fs.readFileSync(mdPath, 'utf-8');
      // Split at +++ to get the body after frontmatter
      const parts = content.split('+++');
      expect(parts.length).toBeGreaterThanOrEqual(3);
      const body = parts.slice(2).join('+++').trim();
      expect(body.length, `${competitor} body should have HTML rows`).toBeGreaterThan(100);
      expect(body).toContain('grid grid-cols-4');
    });

    it(`${competitor} has valid frontmatter extras`, () => {
      const mdPath = path.join(CONTENT_DIR, 'compare', competitor, 'index.md');
      const content = fs.readFileSync(mdPath, 'utf-8');
      expect(content).toContain('competitor_name');
      expect(content).toContain('apexmail_wins');
      expect(content).toContain('competitor_wins');
      expect(content).toContain('verdict_points');
    });
  }
});

/* ── 4. Security Headers ─────────────────────────────────── */

describe('Security headers', () => {
  const REQUIRED_HEADERS = [
    'X-DNS-Prefetch-Control',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Referrer-Policy',
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'Permissions-Policy',
  ];

  it('_headers file exists', () => {
    expect(fs.existsSync(path.join(STATIC_DIR, '_headers'))).toBe(true);
  });

  it('contains all required security headers', () => {
    const content = fs.readFileSync(path.join(STATIC_DIR, '_headers'), 'utf-8');
    const missing = REQUIRED_HEADERS.filter((h) => !content.includes(h));
    expect(missing, `Missing headers: ${missing.join(', ')}`).toHaveLength(0);
  });

  it('has static asset caching rules', () => {
    const content = fs.readFileSync(path.join(STATIC_DIR, '_headers'), 'utf-8');
    expect(content).toContain('Cache-Control');
    expect(content).toContain('immutable');
  });
});

/* ── 5. Static Assets ────────────────────────────────────── */

describe('Static assets referenced in base.html', () => {
  const REQUIRED_ASSETS = [
    'robots.txt',
    'manifest.json',
    'sitemap.xml',
    'patterns/hero-grid.svg',
    'css/input.css',
  ];

  for (const asset of REQUIRED_ASSETS) {
    it(`${asset} exists`, () => {
      expect(fs.existsSync(path.join(STATIC_DIR, asset))).toBe(true);
    });
  }
});

/* ── 6. SEO Meta Tags in base.html ───────────────────────── */

describe('SEO meta tags', () => {
  let baseHtml: string;

  beforeAll(() => {
    baseHtml = fs.readFileSync(path.join(TEMPLATES_DIR, 'base.html'), 'utf-8');
  });

  it('has keywords meta tag', () => {
    expect(baseHtml).toContain('name="keywords"');
  });

  it('has og:image:alt meta tag', () => {
    expect(baseHtml).toContain('og:image:alt');
  });

  it('has hreflang alternate links', () => {
    expect(baseHtml).toContain('hreflang="en-US"');
    expect(baseHtml).toContain('hreflang="x-default"');
  });

  it('has googlebot meta tag with directives', () => {
    expect(baseHtml).toContain('name="googlebot"');
    expect(baseHtml).toContain('max-image-preview');
  });

  it('has canonical link', () => {
    expect(baseHtml).toContain('rel="canonical"');
  });

  it('has JSON-LD schema', () => {
    expect(baseHtml).toContain('application/ld+json');
    expect(baseHtml).toContain('"@type": "Organization"');
  });
});

/* ── 7. Sitemap Coverage ─────────────────────────────────── */

describe('Sitemap coverage', () => {
  const EXPECTED_ROUTES = [
    '/',
    '/features/',
    '/pricing/',
    '/compliance/',
    '/case-studies/',
    '/compare/',
    '/forensic/',
    '/private-cloud/',
    '/api-console/',
    '/status/',
    '/privacy/',
    '/terms/',
    '/cookies/',
    '/dpa/',
    '/sla/',
    '/acceptable-use/',
  ];

  let sitemapContent: string;

  beforeAll(() => {
    sitemapContent = fs.readFileSync(path.join(STATIC_DIR, 'sitemap.xml'), 'utf-8');
  });

  for (const route of EXPECTED_ROUTES) {
    it(`sitemap includes ${route}`, () => {
      expect(sitemapContent).toContain(`https://apexmail.ee${route}`);
    });
  }
});
