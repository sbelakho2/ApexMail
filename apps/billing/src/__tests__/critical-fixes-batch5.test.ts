import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';

// ──────────────────────────────────────────────────────────────────────────────
// Batch 5 tests: Fixes 21-25 (High severity: SDKs, security headers, DB, infra)
// ──────────────────────────────────────────────────────────────────────────────

const root = resolve(__dirname, '../../../..');

// ── Fix 21: HTTPS enforcement across all SDKs ───────────────────────────────
describe('Fix 21: SDK HTTPS enforcement', () => {
  it('PHP SDK rejects non-HTTPS base URLs', () => {
    const php = readFileSync(resolve(root, 'packages/sdk-php/src/Client.php'), 'utf-8');
    expect(php).toContain("'https://'");
    expect(php).toMatch(/throw.*baseUrl must use HTTPS/);
  });

  it('Ruby SDK rejects non-HTTPS base URLs', () => {
    const ruby = readFileSync(resolve(root, 'packages/sdk-ruby/lib/apexmail.rb'), 'utf-8');
    expect(ruby).toContain('baseUrl must use HTTPS');
  });

  it('Java SDK rejects non-HTTPS base URLs', () => {
    const java = readFileSync(
      resolve(root, 'packages/sdk-java/src/main/java/ee/apexmail/ApexMailClient.java'),
      'utf-8'
    );
    expect(java).toContain('"https://"');
    expect(java).toContain('baseUrl must use HTTPS');
  });

  it('Go SDK rejects non-HTTPS base URLs', () => {
    const go = readFileSync(resolve(root, 'packages/sdk-go/apexmail.go'), 'utf-8');
    expect(go).toContain('"https://"');
    expect(go).toContain('baseURL must use HTTPS');
  });
});

// ── Fix 22: Security headers in Next.js web app ─────────────────────────────
describe('Fix 22: Web app security headers', () => {
  const config = readFileSync(resolve(root, 'apps/web/next.config.ts'), 'utf-8');

  it('includes HSTS header', () => {
    expect(config).toContain('Strict-Transport-Security');
  });

  it('includes Permissions-Policy header', () => {
    expect(config).toContain('Permissions-Policy');
  });

  it('includes Content-Security-Policy header', () => {
    expect(config).toContain('Content-Security-Policy');
  });
});

// ── Fix 23: DB verifyCredentials uses explicit columns ───────────────────────
describe('Fix 23: No SELECT * in verifyCredentials', () => {
  const users = readFileSync(
    resolve(root, 'packages/db/src/repositories/users.ts'),
    'utf-8'
  );

  it('does not use SELECT * for credential verification', () => {
    // Find the verifyCredentials method
    const methodMatch = users.match(/verifyCredentials[\s\S]*?SELECT\s+(.*?)\s+FROM/);
    expect(methodMatch).not.toBeNull();
    expect(methodMatch![1]).not.toBe('*');
  });
});

// ── Fix 24: Nginx resolver uses only internal DNS ────────────────────────────
describe('Fix 24: Nginx resolver is internal-only', () => {
  const nginx = readFileSync(resolve(root, 'deploy/nginx/nginx.conf'), 'utf-8');

  it('does not include public DNS servers', () => {
    expect(nginx).not.toContain('1.1.1.1');
    expect(nginx).not.toContain('8.8.8.8');
  });

  it('uses Docker internal DNS', () => {
    expect(nginx).toContain('127.0.0.11');
  });
});

// ── Fix 25: Alertmanager uses service name ───────────────────────────────────
describe('Fix 25: Alertmanager webhook reaches container', () => {
  const alertmanager = readFileSync(resolve(root, 'deploy/alertmanager.yml'), 'utf-8');

  it('does not use 127.0.0.1 for webhook', () => {
    expect(alertmanager).not.toContain('127.0.0.1');
  });

  it('uses a service name for webhook URL', () => {
    expect(alertmanager).toMatch(/url:.*api-server/);
  });
});
