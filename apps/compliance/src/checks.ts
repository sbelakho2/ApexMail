import type { ComplianceCheck } from './types';

export const complianceChecks: ComplianceCheck[] = [
  {
    id: 'CMP-001',
    title: 'PII access logged',
    severity: 'high',
    owner: 'security',
    description: 'Ensure access to PII is logged with actor, scope, and reason.',
  },
  {
    id: 'CMP-002',
    title: 'Data retention policy',
    severity: 'medium',
    owner: 'legal',
    description: 'Retention schedules documented and enforced for all data classes.',
  },
  {
    id: 'CMP-003',
    title: 'Customer export readiness',
    severity: 'low',
    owner: 'support',
    description: 'Export requests fulfilled within SLA with audit trail.',
  },
];
