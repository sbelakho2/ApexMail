/**
 * Wiring Verification Tests — Web Console API Calls
 *
 * Static analysis tests that verify:
 * 1. No frontend files still reference legacy /api/ paths (except billing proxy)
 * 2. All fetch calls use /v1/ prefix matching Rust API routes
 * 3. Billing proxy route file exists and handles required actions
 * 4. Next.js rewrites are configured to forward /v1/ to API_URL
 */

import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

const WEB_ROOT = path.resolve(__dirname, '../../../../apps/web');
const SRC_DIR = path.join(WEB_ROOT, 'src');

/* ── Helpers ─────────────────────────────────────────────── */

function findFilesRecursive(dir: string, exts: string[]): string[] {
  const results: string[] = [];
  if (!fs.existsSync(dir)) return results;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...findFilesRecursive(full, exts));
    } else if (exts.some((ext) => entry.name.endsWith(ext))) {
      results.push(full);
    }
  }
  return results;
}

/* ── Test Data ───────────────────────────────────────────── */

let sourceFiles: string[];

beforeAll(() => {
  sourceFiles = findFilesRecursive(SRC_DIR, ['.ts', '.tsx']);
});

/* ── 1. No Legacy /api/ Fetch Paths ──────────────────────── */

describe('No legacy /api/ fetch paths', () => {
  // Patterns that indicate broken API calls — fetch/sendBeacon to /api/something
  // EXCEPT /api/billing which is a valid Next.js API route proxy
  const LEGACY_API_PATTERN = /(?:fetch|sendBeacon)\s*\(\s*['"`]\/api\/(?!billing)/;

  it('no source files reference /api/ paths (except billing proxy)', () => {
    const violations: string[] = [];

    for (const file of sourceFiles) {
      // Skip the billing route handler itself
      if (file.includes('/api/billing/route.')) continue;

      const content = fs.readFileSync(file, 'utf-8');
      const lines = content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        if (LEGACY_API_PATTERN.test(lines[i])) {
          const rel = path.relative(WEB_ROOT, file);
          violations.push(`${rel}:${i + 1} → ${lines[i].trim()}`);
        }
      }
    }

    expect(
      violations,
      `Legacy /api/ fetch calls found:\n${violations.join('\n')}`,
    ).toHaveLength(0);
  });
});

/* ── 2. All Fetch Calls Use /v1/ Prefix ──────────────────── */

describe('API path consistency', () => {
  // Known API paths that should use /v1/ prefix
  const EXPECTED_V1_PATHS = [
    '/v1/auth/csrf',
    '/v1/auth/login',
    '/v1/auth/register',
    '/v1/auth/logout',
    '/v1/auth/session',
    '/v1/auth/forgot-password',
    '/v1/auth/telemetry',
    '/v1/auth/change-password',
    '/v1/auth/sessions/revoke',
    '/v1/auth/impersonate/end',
    '/v1/account',
    '/v1/client-errors',
  ];

  it('all known API paths are referenced with /v1/ prefix', () => {
    const allContent = sourceFiles
      .filter((f) => !f.includes('/api/billing/route.'))
      .map((f) => fs.readFileSync(f, 'utf-8'))
      .join('\n');

    const missing = EXPECTED_V1_PATHS.filter((p) => !allContent.includes(p));
    expect(
      missing,
      `Expected /v1/ paths not found in source:\n${missing.join('\n')}`,
    ).toHaveLength(0);
  });
});

/* ── 3. Billing Proxy Route ──────────────────────────────── */

describe('Billing proxy route', () => {
  const BILLING_ROUTE = path.join(SRC_DIR, 'app/api/billing/route.ts');

  it('billing proxy route exists', () => {
    expect(fs.existsSync(BILLING_ROUTE)).toBe(true);
  });

  it('handles GET and POST methods', () => {
    const content = fs.readFileSync(BILLING_ROUTE, 'utf-8');
    expect(content).toContain('export async function GET');
    expect(content).toContain('export async function POST');
  });

  it('proxies to billing service', () => {
    const content = fs.readFileSync(BILLING_ROUTE, 'utf-8');
    // Should reference billing service URL
    expect(content).toMatch(/BILLING_URL|billing.*4100|localhost:4100/);
  });

  it('handles checkout and portal actions', () => {
    const content = fs.readFileSync(BILLING_ROUTE, 'utf-8');
    expect(content).toContain('checkout');
    expect(content).toContain('portal');
  });
});

/* ── 4. Next.js Rewrites Configuration ───────────────────── */

describe('Next.js rewrite configuration', () => {
  it('next.config.mjs has /v1/ rewrite to API_URL', () => {
    const configPath = path.join(WEB_ROOT, 'next.config.mjs');
    expect(fs.existsSync(configPath)).toBe(true);
    const content = fs.readFileSync(configPath, 'utf-8');
    // Should have a rewrite from /v1/:path* to API_URL/v1/:path*
    expect(content).toContain('/v1/:path*');
    expect(content).toContain('API_URL');
  });
});

/* ── 5. CSRF Token Management ────────────────────────────── */

describe('CSRF token management', () => {
  it('use-api.ts fetches CSRF from /v1/auth/csrf', () => {
    const useApiPath = path.join(SRC_DIR, 'hooks/use-api.ts');
    expect(fs.existsSync(useApiPath)).toBe(true);
    const content = fs.readFileSync(useApiPath, 'utf-8');
    expect(content).toContain('/v1/auth/csrf');
    // Should NOT contain the old path
    expect(content).not.toContain("'/api/csrf'");
    expect(content).not.toContain('"/api/csrf"');
  });
});
