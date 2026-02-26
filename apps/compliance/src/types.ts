export type ComplianceSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface ComplianceCheck {
  id: string;
  title: string;
  severity: ComplianceSeverity;
  owner: string;
  description: string;
}

export interface ComplianceStatus {
  generatedAt: string;
  checks: ComplianceCheck[];
}
