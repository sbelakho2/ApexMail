import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';

// ──────────────────────────────────────────────────────────────────────────────
// Batch 7 tests: Fixes 36-40
// ──────────────────────────────────────────────────────────────────────────────

const root = resolve(__dirname, '../../../..');

describe('Fix 36: README consistency', () => {
  const readme = readFileSync(resolve(root, 'README.md'), 'utf-8');
  it('diagram port matches table (3010)', () => {
    expect(readme).toContain('Port 3010');
    expect(readme).not.toContain('Port 3000');
  });
  it('pnpm version is 9.15+', () => {
    expect(readme).toContain('pnpm 9.15+');
    expect(readme).not.toContain('pnpm 8.14+');
  });
});

describe('Fix 37: tsconfig.base.json has isolatedModules', () => {
  const tsconfig = JSON.parse(
    readFileSync(resolve(root, 'tsconfig.base.json'), 'utf-8')
  );
  it('isolatedModules is true', () => {
    expect(tsconfig.compilerOptions.isolatedModules).toBe(true);
  });
});

describe('Fix 38: Admin tenants status validation', () => {
  const admin = readFileSync(
    resolve(root, 'apps/billing/src/routes/admin.ts'),
    'utf-8'
  );
  it('validates status against allowlist', () => {
    expect(admin).toContain('VALID_STATUSES');
  });
  it('does not use raw query param directly', () => {
    expect(admin).not.toMatch(/const\s+status\s*=\s*c\.req\.query\('status'\)\s*;/);
  });
});

describe('Fix 39: SMTP error does not leak internals', () => {
  const session = readFileSync(
    resolve(root, 'services/mail-server/crates/smtp-edge/src/session.rs'),
    'utf-8'
  );
  it('does not format error into SMTP response', () => {
    expect(session).not.toContain('Message rejected: {}');
  });
  it('uses generic rejection message', () => {
    expect(session).toContain('550 5.7.1 Message rejected\\r\\n');
  });
});

describe('Fix 40: Python tools — no bare except', () => {
  const audit = readFileSync(
    resolve(root, 'tools/definitive_audit.py'),
    'utf-8'
  );
  const bigfix = readFileSync(
    resolve(root, 'tools/generate_bigfix.py'),
    'utf-8'
  );
  it('definitive_audit uses specific exceptions', () => {
    expect(audit).toContain('except (ValueError, TypeError)');
    expect(audit).not.toMatch(/except\s*:/);
  });
  it('generate_bigfix uses specific exceptions', () => {
    expect(bigfix).toContain('except (OSError, UnicodeDecodeError)');
    expect(bigfix).not.toMatch(/except\s+Exception\s*:\s*\n\s*pass/);
  });
});
