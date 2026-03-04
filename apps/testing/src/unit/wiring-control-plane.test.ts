/**
 * Wiring Verification Tests — Control Plane Proxy
 *
 * Static analysis tests that verify:
 * 1. All API route handlers use proxyToRust()
 * 2. No raw fetch calls to the Rust API backend
 * 3. rust-api.ts exports the expected proxy helpers
 */

import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

const CP_ROOT = path.resolve(__dirname, '../../../../apps/control-plane');
const SRC_DIR = path.join(CP_ROOT, 'src');
const API_DIR = path.join(SRC_DIR, 'app/api');

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

let apiRouteFiles: string[];

beforeAll(() => {
  apiRouteFiles = findFilesRecursive(API_DIR, ['.ts', '.tsx']).filter(
    (f) => path.basename(f) === 'route.ts' || path.basename(f) === 'route.tsx',
  );
});

/* ── 1. Proxy Usage ──────────────────────────────────────── */

describe('Control plane API proxy wiring', () => {
  it('finds API route files', () => {
    expect(apiRouteFiles.length).toBeGreaterThan(0);
  });

  it('all API routes use proxyToRust()', () => {
    const violations: string[] = [];

    for (const file of apiRouteFiles) {
      const content = fs.readFileSync(file, 'utf-8');
      if (!content.includes('proxyToRust')) {
        const rel = path.relative(CP_ROOT, file);
        violations.push(rel);
      }
    }

    expect(
      violations,
      `API routes NOT using proxyToRust():\n${violations.join('\n')}`,
    ).toHaveLength(0);
  });

  it('no API routes use raw fetch to Rust API', () => {
    const violations: string[] = [];
    // Pattern: direct fetch to localhost:PORT or RUST_API_URL that isn't inside rust-api.ts
    const RAW_FETCH_PATTERN = /fetch\s*\(\s*['"`]https?:\/\/.*\/(v1|api)\//;

    for (const file of apiRouteFiles) {
      const content = fs.readFileSync(file, 'utf-8');
      if (RAW_FETCH_PATTERN.test(content)) {
        const rel = path.relative(CP_ROOT, file);
        violations.push(rel);
      }
    }

    expect(
      violations,
      `API routes with raw fetch (should use proxyToRust):\n${violations.join('\n')}`,
    ).toHaveLength(0);
  });
});

/* ── 2. Rust API Helper Module ───────────────────────────── */

describe('rust-api.ts helper module', () => {
  const RUST_API_PATH = path.join(SRC_DIR, 'lib/rust-api.ts');

  it('rust-api.ts exists', () => {
    expect(fs.existsSync(RUST_API_PATH)).toBe(true);
  });

  it('exports proxyToRust function', () => {
    const content = fs.readFileSync(RUST_API_PATH, 'utf-8');
    expect(content).toMatch(/export\s+(async\s+)?function\s+proxyToRust/);
  });

  it('has retry logic', () => {
    const content = fs.readFileSync(RUST_API_PATH, 'utf-8');
    expect(content).toMatch(/retry|retries|attempt/i);
  });

  it('has timeout configuration', () => {
    const content = fs.readFileSync(RUST_API_PATH, 'utf-8');
    expect(content).toMatch(/timeout|AbortSignal|signal/i);
  });
});
