import type { Metadata } from 'next';
import { CaseStudiesHero } from '@/components/case-studies/CaseStudiesHero';
import { CaseStudyList } from '@/components/case-studies/CaseStudyList';
import { CaseStudiesCTA } from '@/components/case-studies/CaseStudiesCTA';

export const metadata: Metadata = {
  title: 'Case Studies | Customer Success Stories',
  description:
    'See how companies use ApexMail to improve email deliverability, ensure compliance, and scale their transactional email infrastructure.',
  openGraph: {
    title: 'Case Studies | Customer Success Stories',
    description:
      'See how companies use ApexMail to improve email deliverability, ensure compliance, and scale their transactional email infrastructure.',
    type: 'website',
    images: ['/og-image.png'],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Case Studies | Customer Success Stories',
    description:
      'See how companies use ApexMail to improve email deliverability, ensure compliance, and scale their transactional email infrastructure.',
    images: ['/og-image.png'],
  },
};

export default function CaseStudiesPage() {
  return (
    <main className="overflow-hidden">
      <CaseStudiesHero />
      <CaseStudyList />
      <CaseStudiesCTA />
    </main>
  );
}
