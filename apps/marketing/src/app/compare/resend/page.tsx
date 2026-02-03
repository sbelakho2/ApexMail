import type { Metadata } from 'next';
import { CompareHero } from '@/components/compare/CompareHero';
import { CompareTable } from '@/components/compare/CompareTable';
import { CompareCTA } from '@/components/compare/CompareCTA';

export const metadata: Metadata = {
  title: 'ApexMail vs Resend | Feature Comparison',
  description:
    'Compare ApexMail to Resend. See why teams choose ApexMail for enterprise features, self-hosting, and built-in CRM.',
  openGraph: {
    title: 'ApexMail vs Resend | Feature Comparison',
    description:
      'Compare ApexMail to Resend. See why teams choose ApexMail for enterprise features, self-hosting, and built-in CRM.',
  },
};

const comparisonData = {
  competitor: {
    name: 'Resend',
    logo: '/logos/resend.svg',
    description: 'Resend is a modern email API for developers with React Email support.',
  },
  categories: [
    {
      name: 'Deliverability',
      features: [
        { name: 'Delivery Rate', apexmail: '99.9%', competitor: '99%', winner: 'apexmail' },
        { name: 'Dedicated IP', apexmail: 'From $50/mo', competitor: 'From $50/mo', winner: 'tie' },
        { name: 'IP Warming', apexmail: 'Automatic geometric', competitor: 'Basic', winner: 'apexmail' },
        { name: 'BIMI Support', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
        { name: 'ARC Signing', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
        { name: 'Reputation Circuit Breaker', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
      ],
    },
    {
      name: 'Compliance',
      features: [
        { name: 'GDPR Automation', apexmail: 'Full DSR handling', competitor: 'Basic', winner: 'apexmail' },
        { name: 'HIPAA BAA', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
        { name: 'Consent Management', apexmail: 'Built-in', competitor: 'No', winner: 'apexmail' },
        { name: 'Audit Logs', apexmail: 'Complete', competitor: 'Basic', winner: 'apexmail' },
        { name: 'Data Residency Options', apexmail: 'EU/US/Custom', competitor: 'US only', winner: 'apexmail' },
      ],
    },
    {
      name: 'Developer Experience',
      features: [
        { name: 'TypeScript SDK', apexmail: 'Yes', competitor: 'Yes', winner: 'tie' },
        { name: 'React Email Support', apexmail: 'Coming soon', competitor: 'Yes', winner: 'competitor' },
        { name: 'Python SDK', apexmail: 'Yes', competitor: 'Yes', winner: 'tie' },
        { name: 'Idempotency Keys', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
        { name: 'Batch Sending', apexmail: '1,000/request', competitor: '100/request', winner: 'apexmail' },
      ],
    },
    {
      name: 'Enterprise',
      features: [
        { name: 'SSO/SAML', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
        { name: 'White-Label', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
        { name: 'Sub-Accounts', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
        { name: 'Self-Hosted Option', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
        { name: 'SLA Guarantees', apexmail: '99.99%', competitor: 'No', winner: 'apexmail' },
        { name: 'Built-in CRM', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
      ],
    },
    {
      name: 'AI & Analytics',
      features: [
        { name: 'Send-Time Optimization', apexmail: 'ML-based', competitor: 'No', winner: 'apexmail' },
        { name: 'Local AI Inference', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
        { name: 'Advanced Analytics', apexmail: 'DuckDB-powered', competitor: 'Basic', winner: 'apexmail' },
        { name: 'Webhooks', apexmail: 'Yes', competitor: 'Yes', winner: 'tie' },
      ],
    },
  ],
  verdict: {
    title: 'Why Choose ApexMail Over Resend?',
    points: [
      'Full enterprise features: SSO, white-label, sub-accounts',
      'HIPAA compliance with BAA for healthcare apps',
      'Self-hosted option for complete data sovereignty',
      'Built-in CRM for sales and marketing alignment',
      'Advanced AI features running locally, no API costs',
      'Higher batch limits (1,000 vs 100 per request)',
    ],
  },
};

export default function CompareResendPage() {
  return (
    <main className="overflow-hidden">
      <CompareHero competitor={comparisonData.competitor} />
      <CompareTable categories={comparisonData.categories} competitorName="Resend" />
      <CompareCTA verdict={comparisonData.verdict} />
    </main>
  );
}
