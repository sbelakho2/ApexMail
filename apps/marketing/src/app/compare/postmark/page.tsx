import type { Metadata } from 'next';
import { CompareHero } from '@/components/compare/CompareHero';
import { CompareTable } from '@/components/compare/CompareTable';
import { CompareCTA } from '@/components/compare/CompareCTA';

export const metadata: Metadata = {
  title: 'ApexMail vs Postmark | Feature Comparison',
  description:
    'Compare ApexMail to Postmark. See why companies choose ApexMail for self-hosting, AI features, and enterprise compliance.',
  openGraph: {
    title: 'ApexMail vs Postmark | Feature Comparison',
    description:
      'Compare ApexMail to Postmark. See why companies choose ApexMail for self-hosting, AI features, and enterprise compliance.',
  },
};

const comparisonData = {
  competitor: {
    name: 'Postmark',
    logo: '/logos/postmark.svg',
    description: 'Postmark by ActiveCampaign focuses on fast, reliable transactional email delivery.',
  },
  categories: [
    {
      name: 'Deliverability',
      features: [
        { name: 'Delivery Rate', apexmail: '99.9%', competitor: '99%', winner: 'tie' },
        { name: 'Average Delivery Time', apexmail: '1.2s', competitor: '~10s', winner: 'apexmail' },
        { name: 'Dedicated IP', apexmail: 'From $50/mo', competitor: 'From $50/mo', winner: 'tie' },
        { name: 'Automatic IP Warming', apexmail: 'Yes', competitor: 'Manual', winner: 'apexmail' },
        { name: 'BIMI Support', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
        { name: 'MTA-STS Support', apexmail: 'Yes', competitor: 'Yes', winner: 'tie' },
      ],
    },
    {
      name: 'Compliance',
      features: [
        { name: 'GDPR Automation', apexmail: 'Full DSR handling', competitor: 'Manual', winner: 'apexmail' },
        { name: 'HIPAA BAA', apexmail: 'Yes', competitor: 'On request', winner: 'apexmail' },
        { name: 'SOC 2 Type II', apexmail: 'Yes', competitor: 'Yes', winner: 'tie' },
        { name: 'Audit Logs', apexmail: 'Complete', competitor: 'Limited', winner: 'apexmail' },
        { name: 'Consent Management', apexmail: 'Built-in', competitor: 'No', winner: 'apexmail' },
      ],
    },
    {
      name: 'Features',
      features: [
        { name: 'Transactional Email', apexmail: 'Yes', competitor: 'Yes', winner: 'tie' },
        { name: 'Marketing Email', apexmail: 'Yes (unified API)', competitor: 'Separate product', winner: 'apexmail' },
        { name: 'Inbound Processing', apexmail: 'Yes', competitor: 'Yes', winner: 'tie' },
        { name: 'Templates', apexmail: 'Multiple engines', competitor: 'Proprietary', winner: 'apexmail' },
        { name: 'Scheduled Sending', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
      ],
    },
    {
      name: 'Enterprise',
      features: [
        { name: 'SSO/SAML', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
        { name: 'White-Label', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
        { name: 'Self-Hosted Option', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
        { name: 'Private Cloud', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
        { name: 'Built-in CRM', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
      ],
    },
    {
      name: 'Pricing',
      features: [
        { name: 'Free Tier', apexmail: '1,000/mo', competitor: '100/mo', winner: 'apexmail' },
        { name: '100K emails/mo', apexmail: '$129', competitor: '$115', winner: 'apexmail' },
        { name: 'Unlimited team members', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
        { name: 'Zero per-email cost option', apexmail: 'Yes (self-hosted)', competitor: 'No', winner: 'apexmail' },
      ],
    },
  ],
  verdict: {
    title: 'Why Choose ApexMail Over Postmark?',
    points: [
      'Unified API for transactional AND marketing email',
      'Self-hosted option for zero per-email costs',
      'Enterprise SSO, white-label, and sub-accounts',
      'Built-in CRM for lead management',
      'Scheduled sending support',
      'More generous free tier (1,000 vs 100 emails/month)',
    ],
  },
} as const;

export default function ComparePostmarkPage() {
  return (
    <main className="overflow-hidden">
      <CompareHero competitor={comparisonData.competitor} />
      <CompareTable categories={comparisonData.categories} competitorName="Postmark" />
      <CompareCTA verdict={comparisonData.verdict} />
    </main>
  );
}
