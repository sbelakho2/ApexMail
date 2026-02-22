import type { Metadata } from 'next';
import { CompareHero } from '@/components/compare/CompareHero';
import { CompareTable } from '@/components/compare/CompareTable';
import { CompareCTA } from '@/components/compare/CompareCTA';

export const metadata: Metadata = {
  title: 'ApexMail vs SendGrid | Feature Comparison',
  description:
    'Compare ApexMail to SendGrid. See why developers choose ApexMail for better deliverability, compliance, and deployment options.',
  openGraph: {
    title: 'ApexMail vs SendGrid | Feature Comparison',
    description:
      'Compare ApexMail to SendGrid. See why developers choose ApexMail for better deliverability, compliance, and deployment options.',
  },
};

const comparisonData = {
  competitor: {
    name: 'SendGrid',
    logo: '/logos/sendgrid.svg',
    description: 'Twilio SendGrid is a popular email delivery platform owned by Twilio.',
  },
  categories: [
    {
      name: 'Deliverability',
      features: [
        { name: 'Delivery Rate', apexmail: '99.9%', competitor: '97%', winner: 'apexmail' },
        { name: 'Dedicated IP', apexmail: 'From Pro ($30/mo add-on)', competitor: 'Pro+ ($89.95/mo)', winner: 'apexmail' },
        { name: 'IP Warming', apexmail: 'Automatic', competitor: 'Manual', winner: 'apexmail' },
        { name: 'DKIM Rotation', apexmail: 'Weekly automatic', competitor: 'Manual', winner: 'apexmail' },
        { name: 'Reputation Circuit Breaker', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
        { name: 'BIMI Support', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
      ],
    },
    {
      name: 'Compliance',
      features: [
        { name: 'GDPR Tools', apexmail: 'Full automation', competitor: 'Basic', winner: 'apexmail' },
        { name: 'HIPAA BAA', apexmail: 'Enterprise plan', competitor: 'Enterprise only', winner: 'tie' },
        { name: 'Data Encryption', apexmail: 'AES-256 at rest', competitor: 'Yes', winner: 'tie' },
        { name: 'Audit Logs', apexmail: 'Growth plan & above', competitor: 'Limited', winner: 'apexmail' },
        { name: 'EU Data Residency', apexmail: 'Yes', competitor: 'Enterprise only', winner: 'apexmail' },
      ],
    },
    {
      name: 'Developer Experience',
      features: [
        { name: 'Time to First Email', apexmail: '<10 seconds', competitor: '~5 minutes', winner: 'apexmail' },
        { name: 'TypeScript SDK', apexmail: 'Full types', competitor: 'Partial', winner: 'apexmail' },
        { name: 'Idempotency Keys', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
        { name: 'Webhook Signatures', apexmail: 'Yes', competitor: 'Yes', winner: 'tie' },
        { name: 'Sandbox Mode', apexmail: 'Yes', competitor: 'Yes', winner: 'tie' },
      ],
    },
    {
      name: 'Pricing',
      features: [
        { name: 'Free Tier', apexmail: '3,000 emails/mo', competitor: '100 emails/day', winner: 'apexmail' },
        { name: '100K emails/mo', apexmail: '$65 (Pro: 150K)', competitor: '$89.95', winner: 'apexmail' },
        { name: 'SSO Included', apexmail: 'Scale & Enterprise plans', competitor: '$500/mo add-on', winner: 'apexmail' },
        { name: 'Private Deployment', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
      ],
    },
    {
      name: 'AI & Intelligence',
      features: [
        { name: 'Send-Time Optimization', apexmail: 'ML-based (Pro+ plans)', competitor: 'Basic', winner: 'apexmail' },
        { name: 'Local AI (No API costs)', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
        { name: 'Subject Line Generator', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
        { name: 'Content Analysis', apexmail: 'Yes', competitor: 'Limited', winner: 'apexmail' },
      ],
    },
  ],
  verdict: {
    title: 'Why Choose ApexMail Over SendGrid?',
    points: [
      'Better deliverability with automatic IP warming and reputation protection',
      'True GDPR compliance automation, not just checkboxes',
      'Local AI features without per-request API costs',
      'Private deployment option for complete data control',
      'SSO on Scale & Enterprise — still far cheaper than SendGrid\'s $500/mo add-on',
    ],
  },
} as const;

export default function CompareSendGridPage() {
  return (
    <main className="overflow-hidden">
      <CompareHero competitor={comparisonData.competitor} />
      <CompareTable categories={comparisonData.categories} competitorName="SendGrid" />
      <CompareCTA verdict={comparisonData.verdict} />
    </main>
  );
}
