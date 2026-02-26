import { describe, expect, it } from 'vitest';
import { complianceChecks, getComplianceStatus } from './index';

describe('compliance checks', () => {
  it('exposes a non-empty checklist', () => {
    expect(complianceChecks.length).toBeGreaterThan(0);
  });

  it('returns status with timestamp', () => {
    const status = getComplianceStatus();
    expect(status.generatedAt).toMatch(/\d{4}-\d{2}-\d{2}T/);
    expect(status.checks.length).toBeGreaterThan(0);
  });
});
