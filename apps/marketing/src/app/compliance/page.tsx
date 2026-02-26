import type { Metadata } from 'next';
import { ComplianceHero } from '@/components/compliance/ComplianceHero';
import { ConsentLedger } from '@/components/compliance/ConsentLedger';
import { AutoDPA } from '@/components/compliance/AutoDPA';
import { RightToBeForgotten } from '@/components/compliance/RightToBeForgotten';
import { AuditTrail } from '@/components/compliance/AuditTrail';
import { ComplianceCTA } from '@/components/compliance/ComplianceCTA';
import { DemoErrorBoundary } from '@/components/ui/DemoErrorBoundary';

export const metadata: Metadata = {
  title: 'Compliance-as-Code | GDPR, HIPAA, SOC 2',
  description: 'The first email API that keeps you out of court. Native consent ledger, auto-generated DPAs, and instant Right-to-be-Forgotten cascades.',
  openGraph: {
    title: 'Compliance-as-Code - ApexMail',
    description: 'The first email API that keeps you out of court.',
    type: 'website',
    images: ['/og-image.png'],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Compliance-as-Code - ApexMail',
    description: 'The first email API that keeps you out of court.',
    images: ['/og-image.png'],
  },
};

export default function CompliancePage() {
  return (
    <>
      <ComplianceHero />
      {/* Illustrative demos below show feature capabilities. Each section is a product illustration, not live customer data. */}
      <DemoErrorBoundary demoName="Consent Ledger"><ConsentLedger /></DemoErrorBoundary>
      <DemoErrorBoundary demoName="Auto DPA"><AutoDPA /></DemoErrorBoundary>
      <DemoErrorBoundary demoName="Right to Be Forgotten"><RightToBeForgotten /></DemoErrorBoundary>
      <DemoErrorBoundary demoName="Audit Trail"><AuditTrail /></DemoErrorBoundary>
      <ComplianceCTA />
    </>
  );
}
