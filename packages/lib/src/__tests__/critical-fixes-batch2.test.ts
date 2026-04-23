import { describe, expect, it, vi } from 'vitest';

const nativeValidatorMock = {
  validateEmail: vi.fn((email: string) => ({
    valid: true,
    email,
    localPart: 'user',
    domain: 'mailinator.com',
    isEai: false,
    isDisposable: true,
    hasMx: true,
    errors: [],
    warnings: [],
  })),
  validateEmailWithMx: vi.fn(async (email: string) => ({
    valid: true,
    email,
    localPart: 'user',
    domain: 'mailinator.com',
    isEai: false,
    isDisposable: true,
    hasMx: true,
    errors: [],
    warnings: [],
  })),
  isDisposableDomain: vi.fn(() => true),
  checkMx: vi.fn(async () => ({
    domain: 'mailinator.com',
    hasMx: true,
    mxRecords: ['mx1.mailinator.com'],
    hasAFallback: false,
  })),
  normalizeEmail: vi.fn((email: string) => email.toLowerCase()),
  initializeDnsResolver: vi.fn(),
};

vi.mock('node:module', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:module')>();
  return {
    ...actual,
    createRequire: () => {
      const originalRequire = actual.createRequire(import.meta.url);
      return (id: string) => {
        if (id === '@apexmail/validator-native') {
          return nativeValidatorMock;
        }
        return originalRequire(id);
      };
    },
  };
});

const { validateEmail, validateEmailSyntax, validationMode } = await import('../validation/index.js');

describe('Fix 9: native syntax validation does not conflate disposable-domain checks', () => {
  it('keeps syntax valid for disposable domains and reports disposability separately', async () => {
    expect(validationMode).toBe('native');
    expect(validateEmailSyntax('user@mailinator.com')).toBe(true);

    const result = await validateEmail('user@mailinator.com', {
      checkMx: false,
      checkDisposable: true,
      checkRoleBased: false,
    });

    expect(result.checks.syntax).toBe(true);
    expect(result.checks.notDisposable).toBe(false);
    expect(result.valid).toBe(false);
  });
});
