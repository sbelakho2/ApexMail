import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';

// ──────────────────────────────────────────────────────────────────────────────
// Batch 6 tests: Fixes 26-35
// ──────────────────────────────────────────────────────────────────────────────

const root = resolve(__dirname, '../../../..');

describe('Fix 26: PHP MockClient uses valid API key and HTTPS', () => {
  const testPhp = readFileSync(resolve(root, 'packages/sdk-php/test.php'), 'utf-8');
  it('default API key matches am_test_ pattern', () => {
    expect(testPhp).toMatch(/am_test_\w{16,}/);
    expect(testPhp).not.toContain("'test_key'");
  });
  it('mock base URL uses HTTPS', () => {
    expect(testPhp).toContain('https://mock.local');
    expect(testPhp).not.toContain('http://mock.local');
  });
});

describe('Fix 27: No unsafe block in field_encryption tests', () => {
  const src = readFileSync(
    resolve(root, 'services/mail-server/crates/enterprise/src/field_encryption.rs'),
    'utf-8'
  );
  it('tampered test does not use unsafe', () => {
    // Find the tampered_ciphertext_fails test
    const testMatch = src.match(/fn tampered_ciphertext_fails[\s\S]*?^\s*\}/m);
    expect(testMatch).not.toBeNull();
    expect(testMatch![0]).not.toContain('unsafe');
  });
});

describe('Fix 28: DLP body truncation is UTF-8 safe', () => {
  const engine = readFileSync(
    resolve(root, 'services/mail-server/crates/dlp-engine/src/engine.rs'),
    'utf-8'
  );
  it('uses floor_char_boundary for truncation', () => {
    expect(engine).toContain('floor_char_boundary');
  });
  it('does not use raw byte slice without boundary check', () => {
    expect(engine).not.toMatch(/&body\[\.\.self\.config\.max_scan_size\]/);
  });
});

describe('Fix 29: XSS analyzer detects <img> tags', () => {
  const xss = readFileSync(
    resolve(root, 'services/mail-server/crates/waf-engine/src/xss_analyzer.rs'),
    'utf-8'
  );
  it('includes <img in dangerous tags list', () => {
    expect(xss).toContain('"<img"');
  });
});

describe('Fix 30: SQL tokenizer has token limit', () => {
  const sql = readFileSync(
    resolve(root, 'services/mail-server/crates/waf-engine/src/sql_analyzer.rs'),
    'utf-8'
  );
  it('has MAX_TOKENS constant', () => {
    expect(sql).toContain('MAX_TOKENS');
  });
  it('breaks loop when limit reached', () => {
    expect(sql).toMatch(/tokens\.len\(\)\s*>=\s*MAX_TOKENS/);
  });
});

describe('Fix 31: Pricing consistency — free tier is 3,000', () => {
  const faq = readFileSync(
    resolve(root, 'apps/marketing-zola/templates/partials/generated/pricing-faq-island.html'),
    'utf-8'
  );
  const plans = readFileSync(
    resolve(root, 'apps/marketing-zola/templates/partials/pricing/plans.html'),
    'utf-8'
  );
  it('FAQ says 3,000 not 10,000', () => {
    expect(faq).not.toContain('10,000 emails');
    expect(faq).toContain('3,000 emails');
  });
  it('plans page says 3,000', () => {
    expect(plans).toContain('3,000 emails/month');
  });
});

describe('Fix 32: Web CTA links to /dashboard', () => {
  const page = readFileSync(resolve(root, 'apps/web/src/app/page.tsx'), 'utf-8');
  it('does not link to non-existent /campaigns', () => {
    expect(page).not.toContain('href="/campaigns"');
  });
  it('links to /dashboard', () => {
    expect(page).toContain('href="/dashboard"');
  });
});

describe('Fix 33: Tailwind accent palette uses --accent-* vars', () => {
  const config = readFileSync(
    resolve(root, 'apps/marketing-zola/tailwind.config.js'),
    'utf-8'
  );
  it('accent palette does not reference --surface-* vars', () => {
    const accentMatch = config.match(/accent:\s*\{[\s\S]*?\},/);
    expect(accentMatch).not.toBeNull();
    expect(accentMatch![0]).not.toContain('--surface-');
    expect(accentMatch![0]).toContain('--accent-');
  });
});

describe('Fix 34: Java SDK close() calls awaitTermination', () => {
  const java = readFileSync(
    resolve(root, 'packages/sdk-java/src/main/java/ee/apexmail/ApexMailClient.java'),
    'utf-8'
  );
  it('calls awaitTermination on retryScheduler', () => {
    expect(java).toContain('awaitTermination');
  });
  it('calls shutdownNow as fallback', () => {
    expect(java).toContain('shutdownNow');
  });
});

describe('Fix 35: DB package.json has no phantom exports', () => {
  const pkg = JSON.parse(
    readFileSync(resolve(root, 'packages/db/package.json'), 'utf-8')
  );
  it('does not export ./migrations', () => {
    expect(pkg.exports['./migrations']).toBeUndefined();
  });
  it('does not export ./schema', () => {
    expect(pkg.exports['./schema']).toBeUndefined();
  });
  it('still exports main entry point', () => {
    expect(pkg.exports['.']).toBe('./dist/index.js');
  });
});
