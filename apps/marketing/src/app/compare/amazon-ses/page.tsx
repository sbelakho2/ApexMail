import type { Metadata } from 'next';
import { CompareHero } from '@/components/compare/CompareHero';
import { CompareTable } from '@/components/compare/CompareTable';
import { CompareCTA } from '@/components/compare/CompareCTA';

export const metadata: Metadata = {
  title: 'ApexMail vs Amazon SES | Feature Comparison',
  description:
    'Compare ApexMail to Amazon SES. See why developers choose ApexMail for better DX, compliance automation, and managed infrastructure.',
  openGraph: {
    title: 'ApexMail vs Amazon SES | Feature Comparison',
    description:
      'Compare ApexMail to Amazon SES. See why developers choose ApexMail for better DX, compliance automation, and managed infrastructure.',
  },
};

const comparisonData = {
  competitor: {
    name: 'Amazon SES',
    logo: '/logos/aws-ses.svg',
    description: 'Amazon Simple Email Service is a low-cost email sending service from AWS.',
  },
  categories: [
    {
      name: 'Setup & Onboarding',
      features: [
        { name: 'Time to First Email', apexmail: '<10 seconds', competitor: '30+ minutes', winner: 'apexmail' },
        { name: 'Credit Card Required', apexmail: 'No', competitor: 'Yes', winner: 'apexmail' },
        { name: 'Sandbox Exit Process', apexmail: 'Instant', competitor: 'Manual review (24-48h)', winner: 'apexmail' },
        { name: 'Domain Verification', apexmail: '1-click DNS', competitor: 'Manual DNS', winner: 'apexmail' },
        { name: 'Learning Curve', apexmail: 'Minutes', competitor: 'Hours/Days', winner: 'apexmail' },
      ],
    },
    {
      name: 'Deliverability',
      features: [
        { name: 'Managed IP Reputation', apexmail: 'Yes', competitor: 'DIY', winner: 'apexmail' },
        { name: 'Automatic IP Warming', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
        { name: 'Reputation Dashboard', apexmail: 'Yes', competitor: 'Basic', winner: 'apexmail' },
        { name: 'DKIM Key Rotation', apexmail: 'Automatic', competitor: 'Manual', winner: 'apexmail' },
        { name: 'Bounce Handling', apexmail: 'Automatic suppression', competitor: 'Manual SNS setup', winner: 'apexmail' },
      ],
    },
    {
      name: 'Developer Experience',
      features: [
        { name: 'REST API', apexmail: 'Modern, intuitive', competitor: 'AWS SDK required', winner: 'apexmail' },
        { name: 'TypeScript SDK', apexmail: 'First-class', competitor: 'Via AWS SDK', winner: 'apexmail' },
        { name: 'Webhooks', apexmail: 'Native', competitor: 'SNS configuration', winner: 'apexmail' },
        { name: 'Idempotency Keys', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
        { name: 'Documentation', apexmail: 'Simple, focused', competitor: 'Complex AWS docs', winner: 'apexmail' },
      ],
    },
    {
      name: 'Compliance',
      features: [
        { name: 'GDPR Tools', apexmail: 'Full automation', competitor: 'None', winner: 'apexmail' },
        { name: 'HIPAA BAA', apexmail: 'Enterprise plan', competitor: 'Part of AWS BAA', winner: 'tie' },
        { name: 'Audit Logs', apexmail: 'Growth plan & above', competitor: 'CloudTrail setup', winner: 'apexmail' },
        { name: 'Consent Management', apexmail: 'Built-in', competitor: 'None', winner: 'apexmail' },
      ],
    },
    {
      name: 'Pricing',
      features: [
        { name: 'Free Tier', apexmail: '3,000/mo forever', competitor: '62,000/mo (from EC2 only)', winner: 'competitor' },
        { name: 'Baseline Cost', apexmail: '$0 (free tier)', competitor: '$0.10/1000 emails', winner: 'apexmail' },
        { name: 'Hidden Costs', apexmail: 'None', competitor: 'Data transfer, SNS, CloudWatch', winner: 'apexmail' },
        { name: 'Price Predictability', apexmail: 'Fixed monthly', competitor: 'Variable', winner: 'apexmail' },
      ],
    },
    {
      name: 'Features',
      features: [
        { name: 'Analytics Dashboard', apexmail: 'Rich, built-in', competitor: 'CloudWatch metrics', winner: 'apexmail' },
        { name: 'Template Management', apexmail: 'Full WYSIWYG', competitor: 'Basic', winner: 'apexmail' },
        { name: 'AI Features', apexmail: 'Send-time optimization (Pro+ plans)', competitor: 'None', winner: 'apexmail' },
        { name: 'Inbound Processing', apexmail: 'Scale+ plans', competitor: 'S3 + Lambda', winner: 'apexmail' },
      ],
    },
  ],
  verdict: {
    title: 'Why Choose ApexMail Over Amazon SES?',
    points: [
      '10-second setup vs 30+ minute AWS configuration',
      'No AWS expertise required—simple REST API',
      'Managed deliverability: IP warming, reputation monitoring, bounce handling',
      'Built-in compliance tools for GDPR and HIPAA (Enterprise plan)',
      'Rich analytics dashboard without CloudWatch complexity',
      'AI-powered features (Pro+): send-time optimization, content analysis',
      'Predictable pricing without hidden AWS charges',
    ],
  },
} as const;

export default function CompareAmazonSESPage() {
  return (
    <main className="overflow-hidden">
      <CompareHero competitor={comparisonData.competitor} />
      <CompareTable categories={comparisonData.categories} competitorName="Amazon SES" />
      <CompareCTA verdict={comparisonData.verdict} />
    </main>
  );
}
