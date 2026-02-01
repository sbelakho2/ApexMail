import type { Metadata } from 'next';
import { ComplianceHero } from '@/components/compliance/ComplianceHero';
import { ConsentLedger } from '@/components/compliance/ConsentLedger';
import { AutoDPA } from '@/components/compliance/AutoDPA';
import { RightToBeForgotten } from '@/components/compliance/RightToBeForgotten';
import { AuditTrail } from '@/components/compliance/AuditTrail';
import { ComplianceCTA } from '@/components/compliance/ComplianceCTA';

export const metadata: Metadata = {
  title: 'Compliance-as-Code | GDPR, HIPAA, SOC 2',
  description: 'The first email API that keeps you out of court. Native consent ledger, auto-generated DPAs, and instant Right-to-be-Forgotten cascades.',
  openGraph: {
    title: 'Compliance-as-Code - ApexMail',
    description: 'The first email API that keeps you out of court.',
  },
};

export default function CompliancePage() {
  return (
    <>
      <ComplianceHero />
      <ConsentLedger />
      <AutoDPA />
      <RightToBeForgotten />
      <AuditTrail />
      <ComplianceCTA />
    </>
  );
}
