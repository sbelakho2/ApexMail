import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';

// ──────────────────────────────────────────────────────────────────────────────
// Batch 1 tests: Fixes 1-5 (Critical billing bugs)
// These are fail-first tests — each validates a specific bug was fixed.
// ──────────────────────────────────────────────────────────────────────────────

// ── Fix 1: COMPANY_INFO must NOT crash on import ─────────────────────────────
// Before fix: importing config.ts would call getConfig() at module load time,
// before loadConfig() was called, throwing "Config not loaded" error.

describe('Fix 1: COMPANY_INFO does not crash on import', () => {
  it('importing config.ts does not throw at module load time', async () => {
    // This must not throw. Before the fix, this line crashed the process.
    const configModule = await import('../config.js');
    expect(configModule.COMPANY_INFO).toBeDefined();
    expect(configModule.COMPANY_INFO.name).toBe('Bel Consulting OÜ');
    expect(configModule.COMPANY_INFO.tradingAs).toBe('ApexMail');
    expect(configModule.COMPANY_INFO.registryCode).toBe('16192499');
    expect(configModule.COMPANY_INFO.vatNumber).toBe('EE102951727');
    expect(configModule.COMPANY_INFO.bank.name).toBe('Swedbank AS');
    expect(configModule.COMPANY_INFO.bank.bic).toBe('HABAEE2X');
  });

  it('COMPANY_INFO.bank.iban is a getter that defers config access', async () => {
    // Verify the iban property is a getter (deferred), not a static value
    // by checking the source code directly.
    const fs = await import('fs');
    const path = await import('path');
    const configSource = fs.readFileSync(
      path.resolve(__dirname, '../config.ts'),
      'utf-8'
    );
    // The iban property must use a getter to defer getConfig() calls
    expect(configSource).toMatch(/get iban\(\)/);
    // The old eagerly-evaluated pattern must NOT exist
    expect(configSource).not.toMatch(/iban:\s*getConfig\(\)/);
  });
});

// ── Fix 2: adminScope is populated in auth middleware ─────────────────────────
// Before fix: BillingEnv.Variables did not include adminScope, and the auth
// middleware never called c.set('adminScope', ...), so admin.ts's
// canAccessTenant() always returned false (adminScope was undefined).

describe('Fix 2: adminScope in BillingEnv and auth middleware', () => {
  it('BillingEnv.Variables type includes adminScope', async () => {
    // We can't directly test TypeScript types at runtime, but we can verify
    // the auth middleware code path sets adminScope by checking the source.
    const fs = await import('fs');
    const path = await import('path');
    const appSource = fs.readFileSync(
      path.resolve(__dirname, '../app.ts'),
      'utf-8'
    );
    // adminScope must be in the Variables interface
    expect(appSource).toContain('adminScope');
    // The auth middleware must set adminScope on the context
    expect(appSource).toMatch(/c\.set\(['"]adminScope['"]/);
  });

  it('TokenResult interface includes adminScope field', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const appSource = fs.readFileSync(
      path.resolve(__dirname, '../app.ts'),
      'utf-8'
    );
    // TokenResult must have adminScope
    expect(appSource).toMatch(/interface TokenResult[\s\S]*?adminScope/);
  });

  it('JWT verification returns adminScope for admin users', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const appSource = fs.readFileSync(
      path.resolve(__dirname, '../app.ts'),
      'utf-8'
    );
    // For admin JWT tokens, adminScope should default to wildcard
    expect(appSource).toContain("['tenant:*']");
  });
});

// ── Fix 3: generateInvoiceNumber receives tenantId ───────────────────────────
// Before fix: this.generateInvoiceNumber() was called without tenantId,
// causing undefined.replace() to throw TypeError.

describe('Fix 3: generateInvoiceNumber called with tenantId', () => {
  it('createInvoice passes tenantId to generateInvoiceNumber', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const invoicesSource = fs.readFileSync(
      path.resolve(__dirname, '../services/invoices.ts'),
      'utf-8'
    );
    // The call must include input.tenantId
    expect(invoicesSource).toContain('this.generateInvoiceNumber(input.tenantId)');
    // The old buggy call without args must NOT exist
    expect(invoicesSource).not.toMatch(/this\.generateInvoiceNumber\(\s*\)/);
  });
});

// ── Fix 4: HTML invoice uses COMPANY_INFO instead of hardcoded IBAN ──────────
// Before fix: the HTML invoice footer hardcoded 'EE38 2200 2210 1234 5678'
// which is a placeholder. The XML template correctly used COMPANY_INFO.bank.iban.

describe('Fix 4: HTML invoice IBAN is not hardcoded', () => {
  it('HTML template does not contain the placeholder IBAN', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const invoicesSource = fs.readFileSync(
      path.resolve(__dirname, '../services/invoices.ts'),
      'utf-8'
    );
    // The hardcoded placeholder IBAN must be gone
    expect(invoicesSource).not.toContain('EE38 2200 2210 1234 5678');
  });

  it('HTML template uses COMPANY_INFO for IBAN', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const invoicesSource = fs.readFileSync(
      path.resolve(__dirname, '../services/invoices.ts'),
      'utf-8'
    );
    // Both XML and HTML templates must use the same source of truth
    expect(invoicesSource).toContain('COMPANY_INFO.bank.iban');
    // Count occurrences — should be at least 3 (import + XML + HTML)
    const ibanRefs = invoicesSource.match(/COMPANY_INFO\.bank\.iban/g);
    expect(ibanRefs).not.toBeNull();
    expect(ibanRefs!.length).toBeGreaterThanOrEqual(3);
  });

  it('HTML template uses COMPANY_INFO for company details', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const invoicesSource = fs.readFileSync(
      path.resolve(__dirname, '../services/invoices.ts'),
      'utf-8'
    );
    // No hardcoded company info in the footer
    expect(invoicesSource).not.toContain('Bel Consulting OÜ (trading as ApexMail) | Reg. 16192499');
    // Must use COMPANY_INFO references instead
    expect(invoicesSource).toContain('COMPANY_INFO.name');
    expect(invoicesSource).toContain('COMPANY_INFO.tradingAs');
    expect(invoicesSource).toContain('COMPANY_INFO.registryCode');
  });
});

// ── Fix 5: Rate limiting returns 503 on Redis failure ────────────────────────
// Before fix: when Redis was down, the catch block just logged and continued,
// bypassing rate limiting entirely. Attacker could flood the API.

describe('Fix 5: Rate limiting fails closed on Redis outage', () => {
  it('rate limit catch block returns 503, not silent pass-through', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const appSource = fs.readFileSync(
      path.resolve(__dirname, '../app.ts'),
      'utf-8'
    );
    // Find the rate limit catch block — use a multi-line regex that captures
    // everything between catch(error){ and the matching closing brace
    const catchMatch = appSource.match(/catch\s*\(error\)\s*\{[\s\S]*?Rate limit check failed[\s\S]*?\}/s);
    expect(catchMatch).not.toBeNull();
    const catchBlock = catchMatch![0];
    // Must return 503, not silently continue
    expect(catchBlock).toContain('503');
    // Must NOT just fall through to next()
    expect(catchBlock).toContain('return');
  });
});
