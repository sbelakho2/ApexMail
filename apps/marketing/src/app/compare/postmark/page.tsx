import type { Metadata } from 'next';
import { CompareHero } from '@/components/compare/CompareHero';
import { CompareTable } from '@/components/compare/CompareTable';
import { CompareCTA } from '@/components/compare/CompareCTA';

export const dynamic = 'force-static';
export const revalidate = 3600;

export const metadata: Metadata = {
  title: 'ApexMail vs Postmark | Feature Comparison',
  description:
    'Compare ApexMail to Postmark. See why companies choose ApexMail for flexible deployment, AI features, and enterprise compliance.',
  openGraph: {
    title: 'ApexMail vs Postmark | Feature Comparison',
    description:
      'Compare ApexMail to Postmark. See why companies choose ApexMail for flexible deployment, AI features, and enterprise compliance.',
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
        { name: 'Dedicated IP', apexmail: 'From $30/mo', competitor: 'From $50/mo', winner: 'apexmail' },
        { name: 'Automatic IP Warming', apexmail: 'Yes', competitor: 'Manual', winner: 'apexmail' },
        { name: 'BIMI Support', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
        { name: 'MTA-STS Support', apexmail: 'Yes', competitor: 'Yes', winner: 'tie' },
      ],
    },
    {
      name: 'Compliance',
      features: [
        { name: 'GDPR Automation', apexmail: 'Full DSR handling', competitor: 'Manual', winner: 'apexmail' },
        { name: 'HIPAA BAA', apexmail: 'Enterprise plan', competitor: 'On request', winner: 'apexmail' },
        { name: 'SOC 2 Controls', apexmail: 'Enterprise plan', competitor: 'Yes', winner: 'tie' },
        { name: 'Audit Logs', apexmail: 'Growth plan & above', competitor: 'Limited', winner: 'apexmail' },
        { name: 'Consent Management', apexmail: 'Built-in', competitor: 'No', winner: 'apexmail' },
      ],
    },
    {
      name: 'Features',
      features: [
        { name: 'Transactional Email', apexmail: 'Yes', competitor: 'Yes', winner: 'tie' },
        { name: 'Marketing Email', apexmail: 'Yes (unified API)', competitor: 'Separate product', winner: 'apexmail' },
        { name: 'Inbound Processing', apexmail: 'Scale+ plans', competitor: 'Yes', winner: 'tie' },
        { name: 'Templates', apexmail: 'Multiple engines', competitor: 'Proprietary', winner: 'apexmail' },
        { name: 'Scheduled Sending', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
      ],
    },
    {
      name: 'Enterprise',
      features: [
        { name: 'SSO/SAML', apexmail: 'Scale & Enterprise', competitor: 'No', winner: 'apexmail' },
        { name: 'White-Label', apexmail: 'Enterprise', competitor: 'No', winner: 'apexmail' },
        { name: 'Private Deployment', apexmail: 'Yes', competitor: 'No', winner: 'apexmail' },
        { name: 'Private Cloud', apexmail: 'Enterprise', competitor: 'No', winner: 'apexmail' },
      ],
    },
    {
      name: 'Pricing',
      features: [
        { name: 'Free Tier', apexmail: '3,000/mo', competitor: '100/mo', winner: 'apexmail' },
        { name: '100K emails/mo', apexmail: '$65 (Pro: 150K)', competitor: '$115', winner: 'apexmail' },
        { name: 'Unlimited team members', apexmail: 'Enterprise plan', competitor: 'No', winner: 'apexmail' },
        { name: 'Zero per-email cost option', apexmail: 'Yes (private deployment)', competitor: 'No', winner: 'apexmail' },
      ],
    },
  ],
  verdict: {
    title: 'Why Choose ApexMail Over Postmark?',
    points: [
      'Unified API for transactional AND marketing email',
      'Private deployment option for zero per-email costs',
      'Enterprise SSO, white-label, and sub-accounts',
      'Scheduled sending support',
      'More generous free tier (3,000 vs 100 emails/month)',
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
