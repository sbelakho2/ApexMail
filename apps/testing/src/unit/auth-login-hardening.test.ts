import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const currentDir = dirname(fileURLToPath(import.meta.url));
const webAppRoot = join(currentDir, '../../../web/src/app');

const loginPageSource = readFileSync(join(webAppRoot, 'login/page.tsx'), 'utf-8');
const forgotPasswordSource = readFileSync(join(webAppRoot, 'forgot-password/page.tsx'), 'utf-8');
const forgotPasswordRouteSource = readFileSync(join(webAppRoot, 'api/auth/forgot-password/route.ts'), 'utf-8');

describe('Web auth hardening coverage', () => {
  it('covers mapped auth errors instead of ambiguous credential copy', () => {
    expect(loginPageSource).toContain('mapAuthError');
    expect(loginPageSource).toContain('auth.error.invalid_credentials');
    expect(loginPageSource).toContain('Incorrect email, password, or verification code.');
  });

  it('covers loading and retry states for login security primitives', () => {
    expect(loginPageSource).toContain('retryAfterSeconds');
    expect(loginPageSource).toContain('setRetryAfterSeconds');
    expect(loginPageSource).toContain('onClick={loadCsrfToken}');
    expect(loginPageSource).toContain('Security check complete');
    expect(loginPageSource).toContain('Redirecting…');
  });

  it('covers forgot-password contract via app API route proxy', () => {
    expect(forgotPasswordSource).toContain("fetch('/api/auth/forgot-password'");
    expect(forgotPasswordRouteSource).toContain('/v1/auth/forgot-password');
  });
});
