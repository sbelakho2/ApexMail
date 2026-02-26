import { complianceChecks } from './checks';
import type { ComplianceStatus } from './types';

export function getComplianceStatus(): ComplianceStatus {
  return {
    generatedAt: new Date().toISOString(),
    checks: complianceChecks,
  };
}

export { complianceChecks };
export type { ComplianceCheck, ComplianceSeverity, ComplianceStatus } from './types';
